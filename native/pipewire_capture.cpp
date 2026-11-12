#include "capture_backend.hpp"
#include "change_notification.hpp"
#include "conversion_policy.hpp"
#include "private_socket_directory.hpp"
#include <gst/allocators/gstdmabuf.h>
#include <gst/allocators/gstfdmemory.h>
#include <gst/gst.h>
#include <gst/video/video-info-dma.h>
#include <gst/video/gstvideometa.h>
#include <atomic>
#include <dbus/dbus.h>
#include <cerrno>
#include <fcntl.h>
#include <limits>
#include <mutex>
#include <poll.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

namespace traverse {
namespace {
struct Caps {
    GstCaps *value;
    explicit Caps(const std::string &text) : value(gst_caps_from_string(text.c_str())) {}
    ~Caps() { if (value) gst_caps_unref(value); }
};
void wake(int fd) noexcept {
    const char byte = 1;
    while (write(fd, &byte, 1) < 0 && errno == EINTR) {}
}
}
std::string PipeWireCapture::target(const PortalSession::Stream &stream) {
    if (!stream.node || stream.node == std::numeric_limits<std::uint32_t>::max() ||
        (stream.serial && !*stream.serial))
        throw std::invalid_argument("Invalid granted PipeWire target");
    return std::to_string(stream.serial ? *stream.serial : stream.node);
}
void PipeWireCapture::validate(const Options &options) {
    Caps caps(options.output_caps);
    if (!caps.value || gst_caps_get_size(caps.value) != 1)
        throw std::invalid_argument("One explicit raw-video output format is required");
    const auto *structure = gst_caps_get_structure(caps.value, 0);
    int numerator = 0, denominator = 0;
    const char *format = gst_structure_get_string(structure, "format");
    if (!gst_structure_has_name(structure, "video/x-raw") || !format ||
        gst_video_format_from_string(format) == GST_VIDEO_FORMAT_UNKNOWN ||
        !gst_structure_get_fraction(structure, "framerate", &numerator, &denominator) ||
        numerator <= 0 || denominator <= 0)
        throw std::invalid_argument("Explicit raw-video format and positive frame rate are required");
    for (const char *field : {"width", "height"}) {
        int value = 0;
        if (gst_structure_has_field(structure, field) &&
            (!gst_structure_get_int(structure, field, &value) || value <= 0))
            throw std::invalid_argument("Invalid explicit output geometry");
    }
    if (options.runtime_directory.empty())
        throw std::invalid_argument("Private capture runtime is required");
}
struct PipeWireCapture::Impl {
    PortalSession::Connection connection; // Last descriptor owner through teardown.
    PrivateSocketDirectory directory;
    PortalSession::Stream stream;
    Options options;
    mutable std::mutex mutex;
    std::mutex stop_mutex;
    Snapshot value;
    ChangeNotification changed;
    int control[2]{-1, -1}, ready[2]{-1, -1};
    std::thread controller;
    GstElement *pipeline = nullptr;
    std::string setup_error;
    bool stopped = false;
    std::atomic<bool> cancelling{false};
    std::atomic<GstElement *> flush_source{nullptr};

    Impl(PortalSession::Connection input, const PortalSession::Stream &selected, Options requested)
        : connection(std::move(input)), directory(requested.runtime_directory),
          stream(selected), options(std::move(requested)) {
        // RT provider contexts use libdbus process-global state. A direct
        // dependency keeps that state loaded across context restarts; global
        // dbus_shutdown is unsafe here because other process users can exist.
        int major = 0, minor = 0, micro = 0;
        dbus_get_version(&major, &minor, &micro);
        value.provider_dbus_version = std::to_string(major) + "." + std::to_string(minor) + "." + std::to_string(micro);
        value.socket_path = (directory.directory / "f").string();
        if (pipe2(control, O_CLOEXEC | O_NONBLOCK))
            throw std::runtime_error("Cannot create capture cancellation channel");
        if (pipe2(ready, O_CLOEXEC | O_NONBLOCK)) {
            close(control[0]); close(control[1]);
            throw std::runtime_error("Cannot create capture setup channel");
        }
        try { controller = std::thread([this] { run(); }); }
        catch (...) { for (int fd : {control[0], control[1], ready[0], ready[1]}) close(fd); throw; }
    }
    ~Impl() {
        stop();
        for (int fd : {control[0], control[1], ready[0], ready[1]}) close(fd);
    }
    void stop() {
        std::lock_guard<std::mutex> lock(stop_mutex);
        if (!stopped) { stopped = true; wake(control[1]); }
        if (controller.joinable()) controller.join();
    }
    void finish(State state, const std::string &error = {}) {
        std::lock_guard<std::mutex> lock(mutex);
        value.state = state; value.error = error;
        changed.notify();
    }
    static GstPadProbeReturn observe(GstPad *, GstPadProbeInfo *info, gpointer data) {
        auto &self = *static_cast<Impl *>(data);
        try { return self.observe(info); }
        catch (const std::exception &error) {
            self.finish(State::Failed, error.what()); wake(self.control[1]);
            return GST_PAD_PROBE_DROP;
        }
    }
    GstPadProbeReturn observe(GstPadProbeInfo *info) {
        if (!connection.valid()) return GST_PAD_PROBE_DROP;
        if (GST_PAD_PROBE_INFO_TYPE(info) & GST_PAD_PROBE_TYPE_EVENT_DOWNSTREAM) {
            auto *event = GST_PAD_PROBE_INFO_EVENT(info);
            if (GST_EVENT_TYPE(event) == GST_EVENT_CAPS) {
                GstCaps *caps = nullptr; gst_event_parse_caps(event, &caps);
                GstVideoInfo video{};
                GstVideoInfoDmaDrm dma{}; gst_video_info_dma_drm_init(&dma);
                const bool drm = gst_video_is_dma_drm_caps(caps);
                if (drm) {
                    if (!gst_video_info_dma_drm_from_caps(&dma, caps))
                        throw std::runtime_error("Invalid negotiated DMA-BUF video layout");
                    video = dma.vinfo;
                } else if (!gst_video_info_from_caps(&video, caps))
                    throw std::runtime_error("Invalid negotiated capture video layout");
                if (!video.width || !video.height || !GST_VIDEO_INFO_N_PLANES(&video))
                    throw std::runtime_error("Missing negotiated capture geometry");
                gchar *text = gst_caps_to_string(caps);
                std::lock_guard<std::mutex> lock(mutex);
                value.caps = text ? text : ""; g_free(text);
                value.width = video.width; value.height = video.height;
                value.format = gst_video_format_to_string(GST_VIDEO_INFO_FORMAT(&video));
                value.strides.clear();
                for (guint i = 0; i < GST_VIDEO_INFO_N_PLANES(&video); ++i)
                    value.strides.push_back(video.stride[i]);
                if (drm) { value.drm_fourcc = dma.drm_fourcc; value.drm_modifier = dma.drm_modifier; }
                else { value.drm_fourcc.reset(); value.drm_modifier.reset(); }
                changed.notify();
            }
        }
        if (GST_PAD_PROBE_INFO_TYPE(info) & GST_PAD_PROBE_TYPE_BUFFER) {
            auto *buffer = GST_PAD_PROBE_INFO_BUFFER(info);
            bool dma = false, other_fd = false;
            if (!gst_buffer_n_memory(buffer)) throw std::runtime_error("Empty capture buffer");
            for (guint i = 0; i < gst_buffer_n_memory(buffer); ++i) {
                auto *memory = gst_buffer_peek_memory(buffer, i);
                if (gst_is_dmabuf_memory(memory)) dma = true;
                else if (gst_is_fd_memory(memory)) other_fd = true;
                else throw std::runtime_error("Capture allocation is not exportable through Unix-FD transport");
            }
            if (dma && other_fd) throw std::runtime_error("Mixed DMA-BUF and non-DMA-BUF capture memory");
            std::lock_guard<std::mutex> lock(mutex);
            if (value.state == State::Failed) return GST_PAD_PROBE_DROP;
            if (!value.width || !value.height) throw std::runtime_error("Capture buffer preceded negotiated geometry");
            if (auto *meta = gst_buffer_get_video_meta(buffer)) {
                if (meta->width != value.width || meta->height != value.height)
                    throw std::runtime_error("Capture buffer geometry differs from negotiated layout");
                std::vector<int> strides(meta->stride,meta->stride+meta->n_planes);
                if (strides!=value.strides) {
                    value.strides=std::move(strides);
                    changed.notify();
                }
            }
            ++value.frames;
            if (dma) ++value.dmabuf_frames; else ++value.fd_frames;
            if (GST_BUFFER_PTS_IS_VALID(buffer)) {
                if (!value.first_pts) value.first_pts = GST_BUFFER_PTS(buffer);
                value.last_pts = GST_BUFFER_PTS(buffer);
            }
            if (value.state != State::Streaming) {
                value.state = State::Streaming;
                changed.notify();
            }
        }
        return GST_PAD_PROBE_OK;
    }
    void setup() noexcept {
        try {
            pipeline = gst_pipeline_new(nullptr);
            if (!pipeline) throw std::runtime_error("Cannot create capture pipeline");
            auto add = [&](const char *factory) {
                auto *element = gst_element_factory_make(factory, nullptr);
                if (!element) throw std::runtime_error(std::string("Missing capture provider: ") + factory);
                gst_bin_add(GST_BIN(pipeline), element); return element;
            };
            auto *source = add("pipewiresrc"), *convert = add("videoconvert");
            auto *rate = add("videorate"), *filter = add("capsfilter"), *sink = add("unixfdsink");
            const auto identity = PipeWireCapture::target(stream);
            g_object_set(source, "fd", connection.descriptor(), "do-timestamp", TRUE, nullptr);
            if (stream.serial) g_object_set(source, "target-object", identity.c_str(), nullptr);
            else g_object_set(source, "path", identity.c_str(), nullptr);
            g_object_set(convert, "n-threads", conversion_threads(), nullptr);
            g_object_set(rate, "drop-only", TRUE, "skip-to-first", TRUE, nullptr);
            Caps caps(options.output_caps); g_object_set(filter, "caps", caps.value, nullptr);
            g_object_set(sink, "socket-path", value.socket_path.c_str(), "sync", FALSE,
                         "wait-for-connection", TRUE, nullptr);
            auto *pad = gst_element_get_static_pad(sink, "sink");
            if (!pad) throw std::runtime_error("Missing capture export pad");
            gst_pad_add_probe(pad, static_cast<GstPadProbeType>(GST_PAD_PROBE_TYPE_BUFFER |
                              GST_PAD_PROBE_TYPE_EVENT_DOWNSTREAM), observe, this, nullptr);
            gst_object_unref(pad);
            if (!gst_element_link_many(source, convert, rate, filter, sink, nullptr))
                throw std::runtime_error("Cannot link native capture transport");
            if (gst_element_set_state(pipeline, GST_STATE_READY) == GST_STATE_CHANGE_FAILURE)
                throw std::runtime_error("Native capture provider failed to open");
            flush_source.store(source);
            if (cancelling.load()) { wake(ready[1]); return; }
            if (gst_element_set_state(pipeline, GST_STATE_PLAYING) == GST_STATE_CHANGE_FAILURE)
                throw std::runtime_error("Native capture provider failed to start");
        } catch (const std::exception &error) { setup_error = error.what(); }
        catch (...) { setup_error = "Native capture setup failed"; }
        wake(ready[1]);
    }
    void run() noexcept {
        State terminal = State::Stopped;
        std::string error;
        std::thread builder;
        GstBus *bus = nullptr;
        try {
            builder = std::thread([this] { setup(); });
            pollfd watched[] = {{control[0], POLLIN, 0},
                {connection.revocation_descriptor(), POLLIN, 0}, {ready[0], POLLIN, 0}};
            for (;;) {
                int result; do { result = poll(watched, 3, -1); } while (result < 0 && errno == EINTR);
                if (result < 0) throw std::runtime_error("Capture lifecycle poll failed");
                if (watched[1].revents || !connection.valid()) { terminal = State::Revoked; break; }
                if (watched[0].revents) break;
                if (watched[2].revents) {
                    builder.join();
                    if (!setup_error.empty()) throw std::runtime_error(setup_error);
                    bus = gst_element_get_bus(pipeline);
                    GPollFD descriptor{}; gst_bus_get_pollfd(bus, &descriptor);
                    watched[2] = {descriptor.fd, POLLIN, 0};
                    break;
                }
            }
            while (bus) {
                pollfd watched[] = {{control[0], POLLIN, 0},
                    {connection.revocation_descriptor(), POLLIN, 0}, {-1, POLLIN, 0}};
                GPollFD descriptor{}; gst_bus_get_pollfd(bus, &descriptor); watched[2].fd = descriptor.fd;
                int result; do { result = poll(watched, 3, -1); } while (result < 0 && errno == EINTR);
                if (result < 0) throw std::runtime_error("Capture bus poll failed");
                if (watched[1].revents || !connection.valid()) { terminal = State::Revoked; break; }
                if (watched[0].revents) break;
                while (auto *message = gst_bus_pop(bus)) {
                    const auto type = GST_MESSAGE_TYPE(message);
                    if (type == GST_MESSAGE_ERROR) {
                        GError *detail = nullptr; gchar *debug = nullptr;
                        gst_message_parse_error(message, &detail, &debug);
                        error = detail ? detail->message : "Native capture failed";
                        g_clear_error(&detail); g_free(debug);
                    } else if (type == GST_MESSAGE_EOS) error = "Desktop capture ended";
                    gst_message_unref(message);
                    if (!error.empty()) break;
                }
                if (!error.empty()) { terminal = State::Failed; break; }
            }
        } catch (const std::exception &failure) { terminal = State::Failed; error = failure.what(); }
        catch (...) { terminal = State::Failed; error = "Native capture lifecycle failed"; }
        // A protocol dup inside GStreamer shares this socket. shutdown wakes a
        // negotiation blocked before its bus exists, without touching authority.
        cancelling.store(true);
        if (auto *source = flush_source.load()) {
            // Element event dispatch takes the state lock held by negotiation.
            // The source pad's bidirectional flush invokes GstBaseSrc unlock
            // without waiting for that state transition to finish first.
            auto *pad = gst_element_get_static_pad(source, "src");
            if (pad) { gst_pad_send_event(pad, gst_event_new_flush_start()); gst_object_unref(pad); }
        }
        shutdown(connection.descriptor(), SHUT_RDWR);
        if (builder.joinable()) builder.join();
        if (bus) gst_object_unref(bus);
        if (pipeline) { gst_element_set_state(pipeline, GST_STATE_NULL); gst_object_unref(pipeline); pipeline = nullptr; }
        connection = PortalSession::Connection();
        std::lock_guard<std::mutex> lock(mutex);
        if (value.state != State::Failed) { value.state = terminal; value.error = error; }
        changed.notify();
    }
};
PipeWireCapture::PipeWireCapture(PortalSession::Connection connection,
                               const PortalSession::Stream &stream, Options options) {
    validate(options); target(stream);
    if (!connection.valid() || connection.protocol() != PortalSession::Connection::Protocol::PipeWire)
        throw std::invalid_argument("A current granted PipeWire connection is required");
    impl = std::make_unique<Impl>(std::move(connection), stream, std::move(options));
}
PipeWireCapture::~PipeWireCapture() = default;
PipeWireCapture::Snapshot PipeWireCapture::snapshot() const {
    std::lock_guard<std::mutex> lock(impl->mutex); return impl->value;
}
void PipeWireCapture::stop() { impl->stop(); }
int PipeWireCapture::state_descriptor() const noexcept { return impl->changed.descriptor(); }
}
