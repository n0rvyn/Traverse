#include "capture_backend.hpp"
#include "notification_probe.hpp"
#include <gst/app/gstappsink.h>
#include <gst/gst.h>
#include <nlohmann/json.hpp>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <set>
#include <thread>
#include <sys/stat.h>
#include <unistd.h>
using Session = traverse::PortalSession;
using Capture = traverse::PipeWireCapture;
using Json = nlohmann::json;
struct Receiver {
    GstElement *pipeline = nullptr, *sink = nullptr;
    GstSample *held = nullptr;
    std::uint64_t frames = 0;
    std::set<std::uint64_t> hashes;
    Json metadata = Json::object();
    bool ended = false, freeze_held = false;
    std::string end_reason;
    ~Receiver() { stop(); }
    void stop() { if (held) { gst_sample_unref(held); held = nullptr; } if (pipeline) { gst_element_set_state(pipeline, GST_STATE_NULL); gst_object_unref(pipeline); pipeline = nullptr; sink = nullptr; } }
    std::uint64_t held_hash() const {
        if (!held) return 0;
        GstMapInfo map{};
        auto *buffer = gst_sample_get_buffer(held);
        if (!gst_buffer_map(buffer, &map, GST_MAP_READ)) throw std::runtime_error("Retained frame is no longer readable");
        std::uint64_t hash = 14695981039346656037ULL;
        for (gsize i = 0; i < map.size; ++i) { hash ^= map.data[i]; hash *= 1099511628211ULL; }
        gst_buffer_unmap(buffer, &map); return hash;
    }
    void start(const std::string &path) {
        ended = false; end_reason.clear();
        pipeline = gst_pipeline_new(nullptr);
        auto *source = gst_element_factory_make("unixfdsrc", nullptr);
        sink = gst_element_factory_make("appsink", nullptr);
        if (!pipeline || !source || !sink) {
            if (source) gst_object_unref(source);
            if (sink) gst_object_unref(sink);
            sink = nullptr; throw std::runtime_error("Actual native receiver unavailable");
        }
        g_object_set(source, "socket-path", path.c_str(), nullptr);
        g_object_set(sink, "sync", FALSE, nullptr);
        gst_bin_add_many(GST_BIN(pipeline), source, sink, nullptr);
        if (!gst_element_link(source, sink) || gst_element_set_state(pipeline, GST_STATE_PLAYING) == GST_STATE_CHANGE_FAILURE)
            throw std::runtime_error("Actual Unix-FD receiver failed to start");
    }
    void drain() {
        if (!sink) return;
        // Test-side observation, never a product queue/count limit.
        while (auto *sample = gst_app_sink_try_pull_sample(GST_APP_SINK(sink), 0)) {
            auto *buffer = gst_sample_get_buffer(sample);
            GstMapInfo map{};
            if (!gst_buffer_map(buffer, &map, GST_MAP_READ)) { gst_sample_unref(sample); throw std::runtime_error("Receiver buffer mapping failed"); }
            std::uint64_t hash = 14695981039346656037ULL;
            for (gsize i = 0; i < map.size; ++i) { hash ^= map.data[i]; hash *= 1099511628211ULL; }
            hashes.insert(hash); ++frames;
            gchar *caps = gst_caps_to_string(gst_sample_get_caps(sample));
            metadata = {{"caps", caps ? caps : ""}, {"bytes", map.size},
                {"pts", GST_BUFFER_PTS_IS_VALID(buffer) ? Json(GST_BUFFER_PTS(buffer)) : Json(nullptr)}};
            g_free(caps); gst_buffer_unmap(buffer, &map);
            if (!freeze_held) {
                if (held) gst_sample_unref(held);
                held = sample; // Retain a real received buffer across authority revocation.
            } else gst_sample_unref(sample);
        }
        auto *bus = gst_element_get_bus(pipeline);
        while (auto *message = gst_bus_pop(bus)) {
            if (GST_MESSAGE_TYPE(message) == GST_MESSAGE_ERROR) {
                GError *error = nullptr; gchar *debug = nullptr;
                gst_message_parse_error(message, &error, &debug);
                ended = true; end_reason = error ? error->message : "Transport error";
                g_clear_error(&error); g_free(debug);
            } else if (GST_MESSAGE_TYPE(message) == GST_MESSAGE_EOS) { ended = true; end_reason = "End of stream"; }
            gst_message_unref(message);
        }
        gst_object_unref(bus);
    }
};
int main(int argc, char **argv) {
    gst_init(&argc, &argv);
    if (argc == 3 && std::string(argv[1]) == "--receive") {
        try {
            Receiver receiver; receiver.start(argv[2]);
            std::string command;
            while (std::getline(std::cin, command)) {
                if (command == "stop") receiver.stop();
                else if (command == "freeze") receiver.freeze_held = true;
                else if (command != "check") throw std::runtime_error("Unknown independent receiver command");
                receiver.drain();
                std::cout << Json{{"receivedFrames", receiver.frames}, {"differentFrames", receiver.hashes.size()},
                    {"receivedMetadata", receiver.metadata}, {"heldReceivedBuffer", receiver.held != nullptr},
                    {"heldBufferHash", receiver.held_hash()}, {"heldBufferFrozen", receiver.freeze_held},
                    {"transportEnded", receiver.ended}, {"endReason", receiver.end_reason}} << std::endl;
                if (command == "stop") break;
            }
            receiver.stop(); gst_deinit(); return 0;
        } catch (const std::exception &error) { gst_deinit(); std::cerr << error.what() << '\n'; return 1; }
    }
    if (argc > 2 || (argc == 2 && std::string(argv[1]) != "--grant-command")) { gst_deinit(); return 2; }
    char pattern[] = "/tmp/capture-probe-XXXXXX";
    const char *made = mkdtemp(pattern); if (!made) return 1;
    const std::string runtime = made;
    try {
        Session session;
        auto end = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        while (session.snapshot().state == Session::State::Probing) {
            if (std::chrono::steady_clock::now() >= end) throw std::runtime_error("Capability test watchdog expired");
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        if (!session.request({3, 1, 2, false, ""})) throw std::runtime_error("Explicit synthetic capture request failed");
        std::unique_ptr<Capture> capture;
        Receiver receiver;
        unsigned generation = 0, readiness_notifications = 0;
        int protocol_descriptor = -1;
        std::uint64_t protocol_inode = 0;
        std::string command;
        bool stopped = false;
        while (std::getline(std::cin, command)) {
            if (command == "capture" || command == "capture-notified" || command == "capture-external" || command == "capture-cancel-now") {
                if (capture) throw std::runtime_error("Capture already running");
                auto granted = session.snapshot();
                if (granted.state != Session::State::Granted || granted.streams.size() != 1)
                    throw std::runtime_error("Actual single-screen grant required");
                auto future = session.open_pipewire_connection();
                if (future.wait_for(std::chrono::seconds(5)) != std::future_status::ready)
                    throw std::runtime_error("Fresh connection test watchdog expired");
                auto connection = future.get();
                struct stat identity{};
                if (fstat(connection.descriptor(), &identity)) throw std::runtime_error("Cannot identify actual protocol connection");
                protocol_descriptor = connection.descriptor(); protocol_inode = identity.st_ino;
                capture = std::make_unique<Capture>(std::move(connection), granted.streams.front(),
                    Capture::Options{runtime, "video/x-raw,format=I420,framerate=30/1"});
                ++generation;
                if (command == "capture-cancel-now") capture->stop();
                else {
                    auto until = std::chrono::steady_clock::now() + std::chrono::seconds(5);
                    while (!std::filesystem::is_socket(capture->snapshot().socket_path)) {
                        auto state = capture->snapshot();
                        if (state.state == Capture::State::Failed) throw std::runtime_error(state.error);
                        if (std::chrono::steady_clock::now() >= until) throw std::runtime_error("Capture listener test watchdog expired");
                        std::this_thread::sleep_for(std::chrono::milliseconds(5));
                    }
                    if (command == "capture" || command == "capture-notified") receiver.start(capture->snapshot().socket_path);
                    if (command == "capture-notified") {
                        notification_until(capture->state_descriptor(),[&] { return capture->snapshot().state==Capture::State::Streaming; });
                        ++readiness_notifications;
                    }
                }
            } else if (command == "revoke-notified") {
                if (!capture) throw std::runtime_error("Capture required");
                drain_notification(capture->state_descriptor());
                session.stop();
                notification_until(capture->state_descriptor(),[&] { return capture->snapshot().state==Capture::State::Revoked; });
            } else if (command == "stop-capture") {
                if (capture) { capture->stop(); }
                receiver.stop();
            } else if (command == "reset-capture") {
                if (capture) { capture->stop(); }
                receiver.stop(); capture.reset();
            } else if (command == "revoke") session.stop();
            else if (command == "stop") {
                if (capture) { capture->stop(); }
                receiver.stop(); session.stop(); stopped = true;
            } else if (command != "check") throw std::runtime_error("Unknown capture probe command");
            receiver.drain();
            auto value = session.snapshot(); Json streams = Json::array();
            for (auto &stream : value.streams) streams.push_back({{"node", stream.node}});
            Json row{{"uid", getuid()}, {"waitingPermission", value.state == Session::State::WaitingPermission},
                {"granted", value.state == Session::State::Granted}, {"stopped", value.state == Session::State::Stopped},
                {"notGranted", value.state == Session::State::NotGranted}, {"error", value.error}, {"streams", streams},
                {"generation", generation}, {"readinessNotifications",readiness_notifications}, {"receivedFrames", receiver.frames}, {"differentFrames", receiver.hashes.size()},
                {"receivedMetadata", receiver.metadata}, {"heldReceivedBuffer", receiver.held != nullptr}};
            if (capture) {
                auto state = capture->snapshot();
                row["capture"] = {{"protocolDescriptor", protocol_descriptor}, {"protocolInode", protocol_inode}, {"exportSocket", state.socket_path}, {"providerDbusVersion", state.provider_dbus_version}, {"state", static_cast<int>(state.state)}, {"error", state.error},
                    {"frames", state.frames}, {"caps", state.caps}, {"width", state.width}, {"height", state.height},
                    {"strides", state.strides}, {"firstPts", state.first_pts ? Json(*state.first_pts) : Json(nullptr)},
                    {"lastPts", state.last_pts ? Json(*state.last_pts) : Json(nullptr)}, {"fdFrames", state.fd_frames}, {"dmabufFrames", state.dmabuf_frames}};
            }
            std::cout << row << std::endl;
        }
        if (capture) { capture->stop(); }
        receiver.stop(); capture.reset(); session.stop();
        std::filesystem::remove(runtime);
        gst_deinit();
        return stopped ? 0 : 1;
    } catch (const std::exception &error) {
        std::filesystem::remove(runtime); gst_deinit(); std::cerr << error.what() << '\n'; return 1;
    }
}
