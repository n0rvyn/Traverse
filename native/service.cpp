#include "common.hpp"
#include "endpoint_settings.hpp"
#include "owner_state.hpp"
#include "readiness_challenge.hpp"
#include "readiness_media_service.hpp"
#include "active_health.hpp"
#include <initializer_list>
#include <arpa/inet.h>
#include <gst/sdp/sdp.h>
#include <gst/webrtc/webrtc.h>

static bool readiness_request(const json &body,std::initializer_list<const char *> fields) {
    if(!body.is_object() || body.size()!=fields.size()+1)return false;
    auto schema=body.find("schemaVersion");
    if(schema==body.end() || !schema->is_number_integer() || *schema!=1)return false;
    for(const auto *field:fields)
        if(!body.contains(field) || !body[field].is_string() || body[field].get_ref<const std::string &>().empty())return false;
    return true;
}
static json readiness_receipt(const traverse::ReadinessChallenge::Receipt &value) {
    return {{"instance",value.instance},{"id",value.id},{"nonce",value.nonce},
            {"observedMonotonicMs",value.observed_monotonic_ms}};
}

// This is operator configuration, never supplied by an unpaired HTTP caller.
static json client_ice_config(const std::string &path, const std::string &stun) {
    if (!path.empty()) {
        std::ifstream file(path);
        if (!file)
            throw std::runtime_error("Cannot open ICE configuration");
        auto config = json::parse(file);
        if (!config.is_object() || !config.contains("iceServers") ||
            !config["iceServers"].is_array())
            throw std::runtime_error("ICE configuration requires an iceServers array");
        for (auto it = config.begin(); it != config.end(); ++it)
            if (it.key() != "iceServers" && it.key() != "iceTransportPolicy")
                throw std::runtime_error("Unsupported ICE configuration field");
        if (config.contains("iceTransportPolicy") && config["iceTransportPolicy"] != "all" &&
            config["iceTransportPolicy"] != "relay")
            throw std::runtime_error("Invalid iceTransportPolicy");
        for (const auto &server : config["iceServers"]) {
            if (!server.is_object() || !server.contains("urls"))
                throw std::runtime_error("ICE server requires urls");
            auto urls = server["urls"];
            if (urls.is_string())
                urls = json::array({urls});
            if (!urls.is_array() || urls.empty())
                throw std::runtime_error("ICE server requires nonempty URLs");
            for (const auto &url : urls) {
                if (!url.is_string())
                    throw std::runtime_error("ICE URL must be a string");
                auto value = url.get<std::string>();
                if (value.rfind("stun:", 0) && value.rfind("stuns:", 0) &&
                    value.rfind("turn:", 0) && value.rfind("turns:", 0))
                    throw std::runtime_error("Invalid ICE URL scheme");
            }
            for (const char *key : {"username", "credential"})
                if (server.contains(key) && !server[key].is_string())
                    throw std::runtime_error("ICE credentials must be strings");
        }
        return config;
    }
    json config = {{"iceServers", json::array()}};
    if (!stun.empty()) {
        auto url = stun;
        auto prefix = url.find("://");
        if (prefix != std::string::npos)
            url.replace(prefix, 3, ":");
        config["iceServers"].push_back({{"urls", url}});
    }
    return config;
}

struct PromiseState {
    std::mutex mutex;
    std::condition_variable cv;
    bool done = false, ok = false;
    GstStructure *reply = nullptr;
    ~PromiseState() {
        if (reply)
            gst_structure_free(reply);
    }
};
static std::unique_ptr<GstStructure, decltype(&gst_structure_free)>
promise_call(const std::function<void(GstPromise *)> &action) {
    auto state = std::make_shared<PromiseState>();
    auto *p = gst_promise_new_with_change_func(
        [](GstPromise *p, gpointer data) {
            auto state = *static_cast<std::shared_ptr<PromiseState> *>(data);
            std::lock_guard lock(state->mutex);
            state->ok = gst_promise_wait(p) == GST_PROMISE_RESULT_REPLIED;
            if (state->ok) {
                const auto *r = gst_promise_get_reply(p);
                if (r)
                    state->reply = gst_structure_copy(r);
            }
            state->done = true;
            state->cv.notify_all();
        },
        new std::shared_ptr<PromiseState>(state),
        [](gpointer d) { delete static_cast<std::shared_ptr<PromiseState> *>(d); });
    action(p);
    std::unique_lock lock(state->mutex);
    bool finished = state->cv.wait_for(lock, std::chrono::seconds(10), [&] { return state->done; });
    lock.unlock();
    if (!finished)
        gst_promise_interrupt(p);
    gst_promise_unref(p);
    if (!finished || !state->ok)
        throw std::runtime_error("WebRTC operation timed out or failed");
    if (state->reply) {
        GError *error = nullptr;
        if (gst_structure_get(state->reply, "error", G_TYPE_ERROR, &error, nullptr) && error) {
            std::string message = error->message;
            g_error_free(error);
            throw std::runtime_error(message);
        }
    }
    auto *reply = state->reply;
    state->reply = nullptr;
    return {reply, gst_structure_free};
}

class Peer : public std::enable_shared_from_this<Peer> {
    Ipc ipc;
    std::string token;
    GstElement *pipeline = nullptr, *rtc = nullptr;
    GstWebRTCDataChannel *channel = nullptr;
    std::mutex input_mutex, stop_mutex, gather_mutex;
    std::condition_variable gather_cv;
    bool gathered = false, cleaned = false;
    inline static std::atomic<unsigned long> next_generation{0};
    unsigned long generation = ++next_generation;
    traverse::ActiveHealth health{generation};
    GstWebRTCDataChannel *health_channel=nullptr;
    mutable std::mutex health_mutex;
    bool health_open=false;
    std::atomic<int> connection_state{GST_WEBRTC_PEER_CONNECTION_STATE_NEW};
    std::atomic<bool> control_open{false}, control_closed{false};
    using Weak = std::weak_ptr<Peer>;
    static void destroy_weak(gpointer d, GClosure *) {
        delete static_cast<Weak *>(d);
    }
    static std::shared_ptr<Peer> get(gpointer d) {
        return static_cast<Weak *>(d)->lock();
    }
    void log_state(const char *phase) {
        bool notified;
        {
            std::lock_guard lock(gather_mutex);
            notified = gathered;
        }
        GstWebRTCICEGatheringState gathering;
        g_object_get(rtc, "ice-gathering-state", &gathering, nullptr);
        GstState current, pending;
        gst_element_get_state(pipeline, &current, &pending, 0);
        std::cerr << "Peer " << generation << " " << phase
                  << " gathering=" << static_cast<int>(gathering) << " notified=" << notified
                  << " frames=" << frames.load()
                  << " pipeline=" << gst_element_state_get_name(current) << "/"
                  << gst_element_state_get_name(pending) << std::endl;
        auto *source = gst_bin_get_by_name(GST_BIN(pipeline), "source");
        auto *pad = gst_element_get_static_pad(source, "src");
        auto *caps = gst_pad_get_current_caps(pad);
        if (caps) {
            auto *text = gst_caps_to_string(caps);
            std::cerr << "Peer " << generation << " source caps " << text << std::endl;
            g_free(text);
            gst_caps_unref(caps);
        } else
            std::cerr << "Peer " << generation << " source has no current caps" << std::endl;
        gst_object_unref(pad);
        gst_object_unref(source);
        GstWebRTCSessionDescription *description = nullptr;
        g_object_get(rtc, "local-description", &description, nullptr);
        if (description) {
            auto *text = gst_sdp_message_as_text(description->sdp);
            std::istringstream lines(text);
            std::string line;
            while (std::getline(lines, line))
                if (line.rfind("a=candidate:", 0) == 0 || line.rfind("m=", 0) == 0 ||
                    line == "a=inactive\r" || line == "a=sendonly\r")
                    std::cerr << "Peer " << generation << " " << line << std::endl;
            g_free(text);
            gst_webrtc_session_description_free(description);
        }
    }
    void reject_input_locked() {
        rejected++;
        try {
            json release={{"type","release"}};ipc.call("/input",&release,token);
        } catch(...) {}
    }
    void input(const json &data) {
        std::lock_guard lock(input_mutex);
        if (!active)
            return;
        try {
            auto event = data.at("event");
            if (!event.is_object())
                throw std::runtime_error("Expected input object");
            ipc.call("/input", &event, token);
            if (active && channel) {
                auto response =
                    json({{"ack", data.value("seq", json{})}, {"sent", data.value("sent", json{})}})
                        .dump();
                GError *error = nullptr;
                gst_webrtc_data_channel_send_string_full(channel, response.c_str(), &error);
                if (error)
                    g_error_free(error);
            }
        } catch (const std::exception &) {
            reject_input_locked();
        }
    }
    void input_channel_message(const gchar *message) {
        json value;
        try {
            value=json::parse(message);
        } catch(const std::exception &) {
            std::lock_guard lock(input_mutex);if(active)reject_input_locked();return;
        }
        if(value.is_object() && value.contains("schemaVersion") && value.contains("type") &&
           (value.at("type")=="request" || value.at("type")=="receipt" || value.at("type")=="challenge")) {
            std::lock_guard lock(health_mutex);++health.rejected;return;
        }
        input(value);
    }
    void health_message(const gchar *message) {
        std::optional<json> response;
        GstWebRTCDataChannel *target=nullptr;
        {
            std::lock_guard lock(health_mutex);
            if(!active || !health_open || !health_channel)return;
            try {
                response=health.receive(json::parse(message),connection_state.load()==GST_WEBRTC_PEER_CONNECTION_STATE_CONNECTED);
                if(response)target=GST_WEBRTC_DATA_CHANNEL(g_object_ref(health_channel));
            } catch(...) {++health.rejected;}
        }
        if(target) {
            auto text=response->dump();GError *error=nullptr;
            gst_webrtc_data_channel_send_string_full(target,text.c_str(),&error);
            if(error)g_error_free(error);
            g_object_unref(target);
        }
    }
    void attach_health(GstWebRTCDataChannel *c) {
        std::unique_lock lock(health_mutex);
        if(!active || health_channel){lock.unlock();gst_webrtc_data_channel_close(c);return;}
        health_channel=GST_WEBRTC_DATA_CHANNEL(g_object_ref(c));
        g_signal_connect_data(c,"on-open",G_CALLBACK(+[](GstWebRTCDataChannel *,gpointer d){
            if(auto p=get(d)){std::lock_guard guard(p->health_mutex);if(p->active)p->health_open=true;}
        }),new Weak(shared_from_this()),destroy_weak,GConnectFlags(0));
        g_signal_connect_data(c,"on-message-string",G_CALLBACK(+[](GstWebRTCDataChannel *,gchar *message,gpointer d){
            if(auto p=get(d))p->health_message(message);
        }),new Weak(shared_from_this()),destroy_weak,GConnectFlags(0));
        g_signal_connect_data(c,"on-close",G_CALLBACK(+[](GstWebRTCDataChannel *,gpointer d){
            if(auto p=get(d)){std::lock_guard guard(p->health_mutex);p->health_open=false;p->health.close();}
        }),new Weak(shared_from_this()),destroy_weak,GConnectFlags(0));
        GstWebRTCDataChannelState initial;g_object_get(c,"ready-state",&initial,nullptr);
        health_open=initial==GST_WEBRTC_DATA_CHANNEL_STATE_OPEN;
    }
    void data_channel(GstWebRTCDataChannel *c) {
        gchar *name=nullptr;g_object_get(c,"label",&name,nullptr);
        bool is_health=name && std::string(name)=="health";g_free(name);
        if(is_health){attach_health(c);return;}
        std::lock_guard lock(input_mutex);
        gchar *label = nullptr;
        g_object_get(c, "label", &label, nullptr);
        bool accept = active && !channel && label && std::string(label) == "input";
        g_free(label);
        if (!accept) {
            gst_webrtc_data_channel_close(c);
            return;
        }
        channel = GST_WEBRTC_DATA_CHANNEL(g_object_ref(c));
        g_signal_connect_data(c, "on-open", G_CALLBACK(+[](GstWebRTCDataChannel *, gpointer d) {
                                  if (auto p = get(d))
                                      p->control_open = true;
                              }),
                              new Weak(shared_from_this()), destroy_weak, GConnectFlags(0));
        g_signal_connect_data(c, "on-message-string",
                              G_CALLBACK(+[](GstWebRTCDataChannel *, gchar *message, gpointer d) {
                                  if (auto p = get(d))
                                      p->input_channel_message(message);
                              }),
                              new Weak(shared_from_this()), destroy_weak, GConnectFlags(0));
        g_signal_connect_data(c, "on-close", G_CALLBACK(+[](GstWebRTCDataChannel *, gpointer d) {
                                  if (auto p = get(d)) {
                                      p->control_closed = true;
                                      if (p->active)
                                          p->failed = true;
                                  }
                              }),
                              new Weak(shared_from_this()), destroy_weak, GConnectFlags(0));
        GstWebRTCDataChannelState initial;
        g_object_get(c, "ready-state", &initial, nullptr);
        if (initial == GST_WEBRTC_DATA_CHANNEL_STATE_OPEN)
            control_open = true;
        if (initial == GST_WEBRTC_DATA_CHANNEL_STATE_CLOSING ||
            initial == GST_WEBRTC_DATA_CHANNEL_STATE_CLOSED)
            control_closed = true;
    }

  public:
    std::atomic<bool> active{true}, failed{false};
    std::atomic<unsigned long> frames{0}, rejected{0};
    Peer(const Ipc &connection, std::string credential)
        : ipc(connection), token(std::move(credential)) {}
    ~Peer() {
        stop();
    }
    json owner_state() const {
        const char *state = "unknown";
        switch (connection_state.load()) {
        case GST_WEBRTC_PEER_CONNECTION_STATE_NEW:
            state = "new";
            break;
        case GST_WEBRTC_PEER_CONNECTION_STATE_CONNECTING:
            state = "connecting";
            break;
        case GST_WEBRTC_PEER_CONNECTION_STATE_CONNECTED:
            state = "connected";
            break;
        case GST_WEBRTC_PEER_CONNECTION_STATE_DISCONNECTED:
            state = "disconnected";
            break;
        case GST_WEBRTC_PEER_CONNECTION_STATE_FAILED:
            state = "failed";
            break;
        case GST_WEBRTC_PEER_CONNECTION_STATE_CLOSED:
            state = "closed";
            break;
        }
        bool live = active.load() && !failed.load();
        json result={{"generation", generation},
                {"peerPresent", true},
                {"peerActive", live},
                {"rtcState", active.load() ? state : "closed"},
                {"controlOpen", live && control_open.load() && !control_closed.load()}};
        {std::lock_guard lock(health_mutex);result["health"]=health.snapshot(live && health_open &&
            connection_state.load()==GST_WEBRTC_PEER_CONNECTION_STATE_CONNECTED);}
        return result;
    }
    void build(const std::string &frame_socket, const std::string &stun, int udp_port, int bitrate,
               bool udp_only) {
        std::lock_guard build_lock(stop_mutex);
        std::cerr << "Peer " << generation << " build" << std::endl;
        if (!active)
            throw std::runtime_error("Peer stopped");
        // SDP/RTX negotiation can precede the first encoded frame. Advertise the
        // same per-peer SSRC that the payloader will use, even before live caps.
        guint32 video_ssrc;
        do {
            if (RAND_bytes(reinterpret_cast<unsigned char *>(&video_ssrc), sizeof(video_ssrc)) != 1)
                throw std::runtime_error("Cannot create video source identity");
        } while (video_ssrc == 0 || video_ssrc == G_MAXUINT32);
        // The socket path is set as a property, never interpolated into a pipeline.
        pipeline =
            parse_pipeline("unixfdsrc name=source ! queue max-size-buffers=1 max-size-bytes=0 "
                           "max-size-time=0 leaky=downstream ! vp8enc name=encoder deadline=1 "
                           "cpu-used=8 threads=2 keyframe-max-dist=60 ! rtpvp8pay pt=96 ssrc=" +
                           std::to_string(video_ssrc) +
                           " ! application/x-rtp,media=video,encoding-name=VP8,payload=96,ssrc=(uint)" +
                           std::to_string(video_ssrc) + " ! webrtcbin "
                           "name=rtc bundle-policy=max-bundle");
        auto *source = gst_bin_get_by_name(GST_BIN(pipeline), "source");
        g_object_set(source, "socket-path", frame_socket.c_str(), nullptr);
        auto *pad = gst_element_get_static_pad(source, "src");
        gst_pad_add_probe(
            pad, GST_PAD_PROBE_TYPE_BUFFER,
            +[](GstPad *, GstPadProbeInfo *, gpointer d) {
                if (auto p = get(d))
                    p->frames++;
                return GST_PAD_PROBE_OK;
            },
            new Weak(shared_from_this()), [](gpointer d) { delete static_cast<Weak *>(d); });
        gst_object_unref(pad);
        gst_object_unref(source);
        auto *encoder = gst_bin_get_by_name(GST_BIN(pipeline), "encoder");
        g_object_set(encoder, "target-bitrate", bitrate, nullptr);
        gst_object_unref(encoder);
        rtc = gst_bin_get_by_name(GST_BIN(pipeline), "rtc");
        // webrtcbin disables generic NACK and RTX by default. Enable recovery
        // before SDP negotiation for both existing and subsequently added tracks.
        g_signal_connect(rtc, "on-new-transceiver",
                         G_CALLBACK(+[](GstElement *, GstWebRTCRTPTransceiver *transceiver,
                                        gpointer) {
                             g_object_set(transceiver, "do-nack", TRUE, nullptr);
                         }),
                         nullptr);
        GArray *transceivers = nullptr;
        g_signal_emit_by_name(rtc, "get-transceivers", &transceivers);
        if (transceivers) {
            for (guint i = 0; i < transceivers->len; ++i)
                g_object_set(g_array_index(transceivers, GstWebRTCRTPTransceiver *, i),
                             "do-nack", TRUE, nullptr);
            g_array_unref(transceivers);
        }
        if (!stun.empty())
            g_object_set(rtc, "stun-server", stun.c_str(), nullptr);
        GstWebRTCICE *ice = nullptr;
        g_object_get(rtc, "ice-agent", &ice, nullptr);
        if (!ice)
            throw std::runtime_error("WebRTC ICE agent unavailable");
        g_object_set(ice, "max-rtp-port", static_cast<guint>(udp_port), "min-rtp-port",
                     static_cast<guint>(udp_port), nullptr);
        if (udp_only) {
            if (!g_object_class_find_property(G_OBJECT_GET_CLASS(ice), "ice-tcp")) {
                g_object_unref(ice);
                throw std::runtime_error("UDP-only diagnostic is unsupported by this ICE agent");
            }
            g_object_set(ice, "ice-tcp", FALSE, nullptr);
        }
        g_object_unref(ice);
        g_signal_connect_data(rtc, "on-data-channel",
                              G_CALLBACK(+[](GstElement *, GstWebRTCDataChannel *c, gpointer d) {
                                  if (auto p = get(d))
                                      p->data_channel(c);
                              }),
                              new Weak(shared_from_this()), destroy_weak, GConnectFlags(0));
        g_signal_connect_data(rtc, "notify::ice-gathering-state",
                              G_CALLBACK(+[](GObject *object, GParamSpec *, gpointer d) {
                                  if (auto p = get(d)) {
                                      GstWebRTCICEGatheringState state;
                                      g_object_get(object, "ice-gathering-state", &state, nullptr);
                                      std::cerr << "Peer " << p->generation << " gathering notify "
                                                << static_cast<int>(state) << std::endl;
                                      if (state == GST_WEBRTC_ICE_GATHERING_STATE_COMPLETE) {
                                          std::lock_guard lock(p->gather_mutex);
                                          p->gathered = true;
                                          p->gather_cv.notify_all();
                                      }
                                  }
                              }),
                              new Weak(shared_from_this()), destroy_weak, GConnectFlags(0));
        g_signal_connect_data(
            rtc, "notify::connection-state",
            G_CALLBACK(+[](GObject *object, GParamSpec *, gpointer d) {
                if (auto p = get(d)) {
                    GstWebRTCPeerConnectionState state;
                    g_object_get(object, "connection-state", &state, nullptr);
                    p->connection_state = state;
                    auto *klass = static_cast<GEnumClass *>(
                        g_type_class_ref(GST_TYPE_WEBRTC_PEER_CONNECTION_STATE));
                    auto *value = g_enum_get_value(klass, state);
                    std::cerr << "WebRTC " << (value ? value->value_nick : "unknown") << std::endl;
                    g_type_class_unref(klass);
                    if (p->active && (state == GST_WEBRTC_PEER_CONNECTION_STATE_FAILED ||
                                      state == GST_WEBRTC_PEER_CONNECTION_STATE_DISCONNECTED ||
                                      state == GST_WEBRTC_PEER_CONNECTION_STATE_CLOSED))
                        p->failed = true;
                }
            }),
            new Weak(shared_from_this()), destroy_weak, GConnectFlags(0));
        if (gst_element_set_state(pipeline, GST_STATE_PLAYING) == GST_STATE_CHANGE_FAILURE)
            throw std::runtime_error("Native media startup failed");
    }
    json answer(const std::string &sdp) {
        std::shared_ptr<GstElement> rtc_owner;
        {
            std::lock_guard lock(stop_mutex);
            if (!active || !rtc)
                throw std::runtime_error("Peer stopped");
            rtc_owner = {GST_ELEMENT(gst_object_ref(rtc)),
                         [](GstElement *p) { gst_object_unref(p); }};
        }
        auto *current_rtc = rtc_owner.get();
        GstSDPMessage *message = nullptr;
        gst_sdp_message_new(&message);
        if (gst_sdp_message_parse_buffer(reinterpret_cast<const guint8 *>(sdp.data()), sdp.size(),
                                         message) != GST_SDP_OK) {
            gst_sdp_message_free(message);
            throw std::runtime_error("Invalid SDP");
        }
        auto *offer = gst_webrtc_session_description_new(GST_WEBRTC_SDP_TYPE_OFFER, message);
        try {
            promise_call([&](auto *p) {
                g_signal_emit_by_name(current_rtc, "set-remote-description", offer, p);
            });
        } catch (...) {
            gst_webrtc_session_description_free(offer);
            throw;
        }
        gst_webrtc_session_description_free(offer);
        auto result = promise_call(
            [&](auto *p) { g_signal_emit_by_name(current_rtc, "create-answer", nullptr, p); });
        GstWebRTCSessionDescription *description = nullptr;
        if (!result ||
            !gst_structure_get(result.get(), "answer", GST_TYPE_WEBRTC_SESSION_DESCRIPTION,
                               &description, nullptr) ||
            !description)
            throw std::runtime_error("No WebRTC answer");
        try {
            promise_call([&](auto *p) {
                g_signal_emit_by_name(current_rtc, "set-local-description", description, p);
            });
        } catch (...) {
            gst_webrtc_session_description_free(description);
            throw;
        }
        gst_webrtc_session_description_free(description);
        {
            std::unique_lock lock(gather_mutex);
            bool completed = gather_cv.wait_for(lock, std::chrono::seconds(15),
                                                [&] { return gathered || !active; });
            lock.unlock();
            if (!completed) {
                log_state("gathering-timeout");
                throw std::runtime_error("ICE gathering timeout");
            }
        }
        if (!active)
            throw std::runtime_error("Sharing stopped during negotiation");
        GstWebRTCSessionDescription *local = nullptr;
        g_object_get(current_rtc, "local-description", &local, nullptr);
        if (!local)
            throw std::runtime_error("No local description");
        gchar *text = gst_sdp_message_as_text(local->sdp);
        json response = {{"type", "answer"}, {"sdp", text}};
        g_free(text);
        gst_webrtc_session_description_free(local);
        return response;
    }
    void check() {
        std::lock_guard lock(stop_mutex);
        if (pipeline)
            try {
                check_bus(pipeline);
            } catch (const std::exception &e) {
                std::cerr << "Media: " << e.what() << '\n';
                failed = true;
            }
    }
    void stop() {
        active = false;
        control_closed = true;
        gather_cv.notify_all();
        std::lock_guard stop_lock(stop_mutex);
        if (cleaned)
            return;
        cleaned = true;
        std::cerr << "Peer " << generation << " stop begin" << std::endl;
        {
            std::lock_guard input_lock(input_mutex);
            try {
                json event = {{"type", "release"}};
                ipc.call("/input", &event, token);
            } catch (...) {
            }
            if (channel)
                gst_webrtc_data_channel_close(channel);
        }
        // Outside input lock: GStreamer can finish callbacks during state teardown.
        GstWebRTCDataChannel *old_health=nullptr;
        {std::lock_guard health_lock(health_mutex);old_health=health_channel;health_channel=nullptr;health_open=false;health.close();}
        if(old_health)gst_webrtc_data_channel_close(old_health);
        stop_pipeline(pipeline);
        if(old_health)g_object_unref(old_health);
        if (channel) {
            g_object_unref(channel);
            channel = nullptr;
        }
        if (rtc) {
            gst_object_unref(rtc);
            rtc = nullptr;
        }
        std::cerr << "Peer " << generation << " stop complete" << std::endl;
    }
};
class Service {
    std::mutex state_mutex, operation_mutex;
    Ipc ipc;
    traverse::ReadinessChallenge readiness;
    std::unique_ptr<traverse::ReadinessMediaService> media;
    std::string token, origin, stun, web_root, base_path;
    int udp_port, bitrate;
    bool udp_only;
    json ice_config;
    std::shared_ptr<Peer> peer;
    unsigned long total_frames = 0;
    bool authorized(const httplib::Request &r) {
        std::lock_guard lock(state_mutex);
        return equal_secret(token, bearer(r));
    }
    std::string credential() {
        std::lock_guard lock(state_mutex);
        return token;
    }

  public:
    Service(std::string socket, std::string expected_origin, std::string server, std::string root,
            int port, int rate, bool only_udp, json client_config, std::string path,bool enable_media,std::string probe_broker)
        : ipc(std::move(socket)), origin(std::move(expected_origin)), stun(std::move(server)),
          web_root(std::move(root)), base_path(std::move(path)), udp_port(port), bitrate(rate),
          udp_only(only_udp), ice_config(std::move(client_config)) {
        if(enable_media)media=std::make_unique<traverse::ReadinessMediaService>(
            std::filesystem::canonical("/proc/self/exe").parent_path()/"traverse-readiness-media",
            static_cast<unsigned short>(udp_port),std::move(probe_broker));
    }
    void stop_media(){if(media)media->stop();}
    void drop(const std::shared_ptr<Peer> &expected = nullptr) {
        std::shared_ptr<Peer> old;
        {
            std::lock_guard lock(state_mutex);
            if (expected && peer != expected)
                return;
            old = std::move(peer);
        }
        if (old) {
            old->stop();
            std::lock_guard lock(state_mutex);
            total_frames += old->frames;
        }
    }
    void owner_routes(httplib::Server &owner) {
        if(media)media->owner_routes(owner);
        auto send=[](httplib::Response &response,json value,int status=200) {
            value.update({{"schemaVersion",1},{"pid",getpid()},
                {"observedMonotonicMs",std::chrono::duration_cast<std::chrono::milliseconds>(
                    Clock::now().time_since_epoch()).count()}});
            reply(response,value,status);
        };
        owner.Post("/readiness/begin",[this,send](const httplib::Request &request,httplib::Response &response) {
            try {
                if(!readiness_request(parse_body(request),{})) {
                    send(response,{{"error","Invalid readiness request"}},400);return;
                }
                auto lease=readiness.begin();
                send(response,{{"ok",true},{"lease",{{"instance",lease.instance},{"id",lease.id},
                    {"token",lease.token},{"nonce",lease.nonce}}}});
            } catch(const json::exception &) { send(response,{{"error","Invalid readiness request"}},400); }
              catch(const std::exception &) { send(response,{{"error","Readiness unavailable"}},503); }
        });
        owner.Post("/readiness/reserve",[this,send](const httplib::Request &request,httplib::Response &response) {
            try {
                auto body=parse_body(request);
                if(!readiness_request(body,{"id"}) || !traverse::ReadinessChallenge::valid_id(body["id"].get<std::string>())) {
                    send(response,{{"error","Invalid readiness request"}},400);return;
                }
                auto lease=readiness.reserve(body["id"].get<std::string>());
                if(!lease){send(response,{{"error","Readiness reservation unavailable"}},409);return;}
                send(response,{{"ok",true},{"lease",{{"instance",lease->instance},{"id",lease->id},
                    {"token",lease->token},{"nonce",lease->nonce}}}});
            } catch(const json::exception &) {send(response,{{"error","Invalid readiness request"}},400);}
              catch(const std::exception &) {send(response,{{"error","Readiness unavailable"}},503);}
        });
        owner.Post("/readiness/cancel",[this,send](const httplib::Request &request,httplib::Response &response) {
            try {
                auto body=parse_body(request);
                if(!readiness_request(body,{"id"}) || !traverse::ReadinessChallenge::valid_id(body["id"].get<std::string>())) {
                    send(response,{{"error","Invalid readiness request"}},400);return;
                }
                if(!readiness.cancel_reserved(body["id"].get<std::string>())) {
                    send(response,{{"error","Readiness reservation unavailable"}},409);return;
                }
                send(response,{{"ok",true}});
            } catch(const json::exception &) {send(response,{{"error","Invalid readiness request"}},400);}
              catch(const std::exception &) {send(response,{{"error","Readiness unavailable"}},503);}
        });
        owner.Post("/readiness/inspect",[this,send](const httplib::Request &request,httplib::Response &response) {
            try {
                auto body=parse_body(request);
                if(!readiness_request(body,{"id"})) {
                    send(response,{{"error","Invalid readiness request"}},400);return;
                }
                auto state=readiness.inspect(body["id"].get<std::string>());
                if(!state) { send(response,{{"error","Readiness lease unavailable"}},404);return; }
                json probe={{"instance",state->instance},{"id",state->id},
                    {"state",state->receipt?"observed":"issued"}};
                if(state->receipt)probe["receipt"]=readiness_receipt(*state->receipt);
                send(response,{{"ok",true},{"probe",probe}});
            } catch(const json::exception &) { send(response,{{"error","Invalid readiness request"}},400); }
              catch(const std::exception &) { send(response,{{"error","Readiness unavailable"}},503); }
        });
        owner.Post("/readiness/end",[this,send](const httplib::Request &request,httplib::Response &response) {
            try {
                auto body=parse_body(request);
                if(!readiness_request(body,{"id"})) {
                    send(response,{{"error","Invalid readiness request"}},400);return;
                }
                if(!readiness.end(body["id"].get<std::string>())) {
                    send(response,{{"error","Readiness lease unavailable"}},404);return;
                }
                send(response,{{"ok",true}});
            } catch(const json::exception &) { send(response,{{"error","Invalid readiness request"}},400); }
              catch(const std::exception &) { send(response,{{"error","Readiness unavailable"}},503); }
        });
        owner.Get("/state", [this](const httplib::Request &, httplib::Response &response) {
            std::shared_ptr<Peer> current;
            {
                std::lock_guard lock(state_mutex);
                current = peer;
            }
            auto value = current ? current->owner_state()
                                 : json{{"generation", 0},
                                        {"peerPresent", false},
                                        {"peerActive", false},
                                        {"rtcState", "none"},
                                        {"controlOpen", false}};
            value.update(
                {{"schemaVersion", 1},
                 {"pid", getpid()},
                 {"observedMonotonicMs", std::chrono::duration_cast<std::chrono::milliseconds>(
                                             Clock::now().time_since_epoch())
                                             .count()}});
            reply(response, value);
        });
    }
    void routes(httplib::Server &server) {
        auto literal = [](const std::string &path) {
            std::string result;
            for (char c : path) {
                if (std::string_view(R"(\.^$|()[]{}*+?)").find(c) != std::string_view::npos)
                    result += '\\';
                result += c;
            }
            return result;
        };
        auto route = [&](const std::string &suffix) { return literal(base_path + suffix); };
        if(media)media->public_routes(server,route("api/readiness/media/"));
        server.set_pre_routing_handler([this](const httplib::Request &r, httplib::Response &s) {
            if (r.path.rfind(base_path + "api/", 0) == 0 && r.method == "POST" &&
                r.get_header_value("Origin") != origin) {
                reply(s, {{"error", "Origin rejected"}}, 403);
                return httplib::Server::HandlerResponse::Handled;
            }
            return httplib::Server::HandlerResponse::Unhandled;
        });
        server.set_post_routing_handler([](const httplib::Request &, httplib::Response &s) {
            s.set_header("Cache-Control", "no-store");
            s.set_header("X-Content-Type-Options", "nosniff");
            s.set_header("Referrer-Policy", "no-referrer");
            s.set_header("Content-Security-Policy",
                         "default-src 'self'; connect-src 'self'; media-src 'self' blob:; "
                         "style-src 'self'; script-src 'self'; frame-ancestors 'none'");
        });
        if (base_path != "/") {
            server.Get(literal(base_path.substr(0, base_path.size() - 1)),
                       [this](const httplib::Request &, httplib::Response &s) {
                           s.set_redirect(base_path, 308);
                       });
        }
        for (auto entry : std::vector<std::pair<std::string, std::string>>{
                 {"", "index.html"}, {"client.js", "client.js"}, {"style.css", "style.css"}}) {
            server.Get(route(entry.first), [this, name = entry.second](const httplib::Request &,
                                                                       httplib::Response &s) {
                std::ifstream file(std::filesystem::path(web_root) / name, std::ios::binary);
                if (!file) {
                    s.status = 404;
                    return;
                }
                std::ostringstream data;
                data << file.rdbuf();
                s.set_content(data.str(), name == "index.html"  ? "text/html"
                                          : name == "client.js" ? "text/javascript"
                                                                : "text/css");
            });
        }
        // Only a private-owner-issued one-use lease can reach this route.
        // It never takes operation_mutex, leases the controller or builds Peer.
        server.Post(route("api/readiness/challenge"),[this](const httplib::Request &request,httplib::Response &response) {
            try {
                auto token=bearer(request);
                if(!readiness.valid_token(token)) {
                    reply(response,{{"error","Readiness lease unavailable"}},403);return;
                }
                auto body=parse_body(request);
                if(!readiness_request(body,{"id","nonce"})) {
                    reply(response,{{"error","Invalid readiness request"}},400);return;
                }
                auto receipt=readiness.consume(body["id"].get<std::string>(),token,
                    body["nonce"].get<std::string>());
                if(!receipt) { reply(response,{{"error","Readiness lease unavailable"}},403);return; }
                reply(response,{{"schemaVersion",1},{"receipt",readiness_receipt(*receipt)}});
            } catch(const json::exception &) { reply(response,{{"error","Invalid readiness request"}},400); }
              catch(const std::exception &) { reply(response,{{"error","Readiness unavailable"}},503); }
        });
        server.Post(route("api/pair"), [this](const httplib::Request &r, httplib::Response &s) {
            std::lock_guard op(operation_mutex);
            try {
                if (!credential().empty()) {
                    reply(s,
                          {{"error",
                            "A controller is already paired. Revoke locally to pair another."}},
                          409);
                    return;
                }
                auto body = parse_body(r);
                auto result = ipc.call("/pair", &body);
                if(media)media->preempt();
                {
                    std::lock_guard lock(state_mutex);
                    token = result.at("token").get<std::string>();
                }
                result.update(ice_config);
                reply(s, result);
            } catch (const std::exception &e) {
                reply(s, {{"error", e.what()}}, 403);
            }
        });
        server.Post(route("api/offer"), [this](const httplib::Request &r, httplib::Response &s) {
            std::lock_guard op(operation_mutex);
            if (!authorized(r)) {
                reply(s, {{"error", "Pair first"}}, 403);
                return;
            }
            try {
                auto body = parse_body(r);
                if (body.value("type", std::string{}) != "offer" || !body.contains("sdp") ||
                    !body["sdp"].is_string()) {
                    reply(s, {{"error", "Expected SDP offer"}}, 400);
                    return;
                }
                auto lease = credential();
                json release = {{"type", "release"}};
                ipc.call("/input", &release, lease);
                drop();
                if(media)media->preempt();
                auto state = ipc.call("/state");
                auto next = std::make_shared<Peer>(ipc, lease);
                {
                    std::lock_guard lock(state_mutex);
                    peer = next;
                }
                next->build(state.at("frameSocket").get<std::string>(), stun, udp_port, bitrate,
                            udp_only);
                auto answer = next->answer(body.at("sdp").get<std::string>());
                reply(s, answer);
            } catch (const std::exception &e) {
                drop();
                reply(s, {{"error", e.what()}}, 400);
            }
        });
        server.Post(route("api/disconnect"),
                    [this](const httplib::Request &r, httplib::Response &s) {
                        std::lock_guard op(operation_mutex);
                        if (!authorized(r)) {
                            reply(s, {{"error", "Pair first"}}, 403);
                            return;
                        }
                        drop();
                        reply(s, {{"ok", true}});
                    });
        server.Get(route("api/stats"), [this](const httplib::Request &r, httplib::Response &s) {
            if (!authorized(r)) {
                reply(s, {{"error", "Pair first"}}, 403);
                return;
            }
            try {
                auto state = ipc.call("/state");
                std::lock_guard lock(state_mutex);
                reply(s, {{"framesCaptured", total_frames + (peer ? peer->frames.load() : 0)},
                          {"rejected", peer ? peer->rejected.load() : 0},
                          {"adapter", state}});
            } catch (const std::exception &e) {
                reply(s, {{"error", e.what()}}, 503);
            }
        });
    }
    void tick() {
        while (g_main_context_iteration(nullptr, FALSE)) {
        }
        std::unique_lock op(operation_mutex, std::try_to_lock);
        if (!op.owns_lock())
            return;
        try {
            auto state = ipc.call("/state");
            if (!state.value("armed", false) || !state.value("paired", false)) {
                drop();
                if(media)media->owner_state(state.value("armed",false),state.value("paired",false));
                std::lock_guard lock(state_mutex);
                token.clear();
                return;
            }
            if(media)media->owner_state(true,true);
            std::shared_ptr<Peer> p;
            {
                std::lock_guard lock(state_mutex);
                p = peer;
            }
            if (p) {
                if (p->failed) {
                    drop(p);
                    return;
                }
                p->check();
                if (p->failed)
                    drop(p);
            }
        } catch (const std::exception &) {
            drop();
            if(media)media->preempt();
            std::lock_guard lock(state_mutex);
            token.clear();
        }
    }
};
int main(int argc, char **argv) {
    try {
        Args args(argc, argv);
        guard_supervisor(args);
        auto cert = args.get("--cert"), key = args.get("--key"), origin = args.get("--origin");
        const bool internal_http = args.has("--internal-http");
        auto host = args.get("--host", internal_http ? "127.0.0.1" : "0.0.0.0");
        if (internal_http && (host != "127.0.0.1" && host != "::1"))
            throw std::runtime_error("Internal HTTP requires an explicit loopback address");
        if (internal_http && origin.rfind("https://", 0) != 0)
            throw std::runtime_error("Internal HTTP requires the public HTTPS origin");
        if (origin.empty() || (!internal_http && (cert.empty() || key.empty())))
            throw std::runtime_error("Required: --cert FILE --key FILE --origin https://HOST:PORT");
        auto base_path =
            traverse::EndpointSettings::normalize_base_path(args.get("--base-path", "/"));
        if (args.has("--check-udp-port")) {
            const auto media_port = std::stoi(args.get("--udp-port"));
            if (media_port < 1 || media_port > 65535)
                throw std::runtime_error("Invalid media UDP port");
            for (int family : {AF_INET, AF_INET6}) {
                int fd = socket(family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
                if (fd < 0) {
                    if (family == AF_INET6 && errno == EAFNOSUPPORT)
                        continue;
                    throw std::runtime_error("Cannot inspect media UDP port");
                }
                sockaddr_in v4{};
                sockaddr_in6 v6{};
                v4.sin_family = AF_INET;
                v4.sin_port = htons(media_port);
                v6.sin6_family = AF_INET6;
                v6.sin6_port = htons(media_port);
                int only = 1;
                if (family == AF_INET6 &&
                    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &only, sizeof(only))) {
                    close(fd);
                    throw std::runtime_error("Cannot inspect IPv6 media UDP port");
                }
                int bound = family == AF_INET
                                ? bind(fd, reinterpret_cast<sockaddr *>(&v4), sizeof(v4))
                                : bind(fd, reinterpret_cast<sockaddr *>(&v6), sizeof(v6));
                const int error = errno;
                close(fd);
                if (bound)
                    throw std::runtime_error("Cannot bind media UDP port: " +
                                             std::string(std::strerror(error)));
            }
        }
        gst_init(nullptr, nullptr);
        // Load the real peer plugins before advertising a ready endpoint. The
        // low-port path uses only the installed, root-owned plugin registry.
        for (const char *name : {"unixfdsrc", "queue", "vp8enc", "rtpvp8pay", "rtprtxsend",
                                 "rtprtxreceive", "webrtcbin", "nicesrc", "dtlsenc", "srtpenc",
                                 "sctpenc"}) {
            auto *element = gst_element_factory_make(name, nullptr);
            if (!element)
                throw std::runtime_error(std::string("Required media plugin unavailable: ") + name);
            gst_object_unref(element);
        }
        std::signal(SIGINT, signal_stop);
        std::signal(SIGTERM, signal_stop);
        std::signal(SIGPIPE, SIG_IGN);
        Service service(args.get("--socket", default_socket()), origin,
                        args.get("--stun", "stun://stun.cloudflare.com:3478"),
                        args.get("--web", "web"), std::stoi(args.get("--udp-port", "50000")),
                        std::stoi(args.get("--bitrate", "6000000")), args.has("--udp-only"),
                        client_ice_config(args.get("--ice-config"),
                                          args.get("--stun", "stun://stun.cloudflare.com:3478")),
                        base_path,args.has("--media-readiness"),args.get("--media-probe-socket"));
        std::unique_ptr<httplib::Server> server;
        if (internal_http) {
            server = std::make_unique<httplib::Server>();
        } else {
            auto tls = std::make_unique<httplib::SSLServer>(cert.c_str(), key.c_str());
            if (!tls->is_valid())
                throw std::runtime_error("TLS certificate/key unavailable");
            server = std::move(tls);
        }
        // Rebind after our own TCP connections close, without sharing a live port.
        // cpp-httplib's default chooses SO_REUSEPORT on Linux instead.
        server->set_socket_options([](auto socket) {
            int enabled = 1;
            if (setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)))
                throw std::runtime_error("Cannot configure exclusive service listener");
        });
        service.routes(*server);
        std::unique_ptr<traverse::OwnerStateListener> owner;
        if (args.has("--owner-socket"))
            owner = std::make_unique<traverse::OwnerStateListener>(
                args.get("--owner-socket"),
                [&](auto &listener) { service.owner_routes(listener); });
        int port = std::stoi(args.get("--port", "8443"));
        if (!server->bind_to_port(host, port))
            throw std::runtime_error("Cannot bind service listener");
        std::atomic<bool> listener_failed{false};
        std::thread listener([&] {
            if (!server->listen_after_bind())
                listener_failed = true;
        });
        std::cout << (internal_http ? "Internal HTTP backend for " : "Listening at ") << origin
                  << (base_path == "/" ? "" : base_path) << std::endl;
        while (!stopping && !listener_failed && !(owner && owner->failed())) {
            service.tick();
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        service.stop_media();
        server->stop();
        listener.join();
        service.drop();
        bool owner_failed = owner && owner->failed();
        owner.reset();
        if (listener_failed || owner_failed)
            throw std::runtime_error("Service listener failed");
        return 0;
    } catch (const std::exception &e) {
        std::cerr << "Service: " << e.what() << '\n';
        return 1;
    }
}
