#include "common.hpp"
#include <gst/sdp/sdp.h>
#include <gst/webrtc/webrtc.h>

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
    void input(const gchar *message) {
        std::lock_guard lock(input_mutex);
        if (!active)
            return;
        try {
            auto data = json::parse(message);
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
            rejected++;
            try {
                json release = {{"type", "release"}};
                ipc.call("/input", &release, token);
            } catch (...) {
            }
        }
    }
    void data_channel(GstWebRTCDataChannel *c) {
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
        g_signal_connect_data(c, "on-message-string",
                              G_CALLBACK(+[](GstWebRTCDataChannel *, gchar *message, gpointer d) {
                                  if (auto p = get(d))
                                      p->input(message);
                              }),
                              new Weak(shared_from_this()), destroy_weak, GConnectFlags(0));
        g_signal_connect_data(c, "on-close", G_CALLBACK(+[](GstWebRTCDataChannel *, gpointer d) {
                                  if (auto p = get(d); p && p->active)
                                      p->failed = true;
                              }),
                              new Weak(shared_from_this()), destroy_weak, GConnectFlags(0));
    }

  public:
    std::atomic<bool> active{true}, failed{false};
    std::atomic<unsigned long> frames{0}, rejected{0};
    Peer(const Ipc &connection, std::string credential)
        : ipc(connection), token(std::move(credential)) {}
    ~Peer() {
        stop();
    }
    void build(const std::string &frame_socket, const std::string &stun, int udp_port, int bitrate,
               bool udp_only) {
        std::lock_guard build_lock(stop_mutex);
        std::cerr << "Peer " << generation << " build" << std::endl;
        if (!active)
            throw std::runtime_error("Peer stopped");
        // The socket path is set as a property, never interpolated into a pipeline.
        pipeline =
            parse_pipeline("unixfdsrc name=source ! queue max-size-buffers=1 max-size-bytes=0 "
                           "max-size-time=0 leaky=downstream ! vp8enc name=encoder deadline=1 "
                           "cpu-used=8 threads=2 keyframe-max-dist=60 ! rtpvp8pay pt=96 ! "
                           "application/x-rtp,media=video,encoding-name=VP8,payload=96 ! webrtcbin "
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
        stop_pipeline(pipeline);
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
    std::string token, origin, stun, web_root;
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
            int port, int rate, bool only_udp, json client_config)
        : ipc(std::move(socket)), origin(std::move(expected_origin)), stun(std::move(server)),
          web_root(std::move(root)), udp_port(port), bitrate(rate), udp_only(only_udp),
          ice_config(std::move(client_config)) {}
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
    void routes(httplib::Server &server) {
        server.set_pre_routing_handler([this](const httplib::Request &r, httplib::Response &s) {
            if (r.path.rfind("/api/", 0) == 0 && r.method == "POST" &&
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
        for (auto entry : std::vector<std::pair<std::string, std::string>>{
                 {"/", "index.html"}, {"/client.js", "client.js"}, {"/style.css", "style.css"}}) {
            server.Get(entry.first, [this, name = entry.second](const httplib::Request &,
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
        server.Post("/api/pair", [this](const httplib::Request &r, httplib::Response &s) {
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
        server.Post("/api/offer", [this](const httplib::Request &r, httplib::Response &s) {
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
        server.Post("/api/disconnect", [this](const httplib::Request &r, httplib::Response &s) {
            std::lock_guard op(operation_mutex);
            if (!authorized(r)) {
                reply(s, {{"error", "Pair first"}}, 403);
                return;
            }
            drop();
            reply(s, {{"ok", true}});
        });
        server.Get("/api/stats", [this](const httplib::Request &r, httplib::Response &s) {
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
                std::lock_guard lock(state_mutex);
                token.clear();
                return;
            }
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
        gst_init(nullptr, nullptr);
        std::signal(SIGINT, signal_stop);
        std::signal(SIGTERM, signal_stop);
        std::signal(SIGPIPE, SIG_IGN);
        Service service(args.get("--socket", default_socket()), origin,
                        args.get("--stun", "stun://stun.cloudflare.com:3478"),
                        args.get("--web", "web"), std::stoi(args.get("--udp-port", "50000")),
                        std::stoi(args.get("--bitrate", "6000000")), args.has("--udp-only"),
                        client_ice_config(args.get("--ice-config"),
                                          args.get("--stun", "stun://stun.cloudflare.com:3478")));
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
        int port = std::stoi(args.get("--port", "8443"));
        if (!server->bind_to_port(host, port))
            throw std::runtime_error("Cannot bind service listener");
        std::atomic<bool> listener_failed{false};
        std::thread listener([&] {
            if (!server->listen_after_bind())
                listener_failed = true;
        });
        std::cout << (internal_http ? "Internal HTTP backend for " : "Listening at ") << origin
                  << std::endl;
        while (!stopping && !listener_failed) {
            service.tick();
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        server->stop();
        listener.join();
        service.drop();
        if (listener_failed)
            throw std::runtime_error("Service listener failed");
        return 0;
    } catch (const std::exception &e) {
        std::cerr << "Service: " << e.what() << '\n';
        return 1;
    }
}
