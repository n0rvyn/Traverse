#include <atomic>
#include <filesystem>
#include <fstream>
#include <gst/gst.h>
#include <iostream>
#include <nlohmann/json.hpp>
#include <openssl/rand.h>
#include <srtp2/srtp.h>
using json = nlohmann::json;

static bool provider_assets(json &result) {
    const char *prefix = getenv("TRAVERSE_RUNTIME_PREFIX");
    if (!prefix)
        return true; // Unbundled development builds still test the actual crypto path.
    std::ifstream file(std::filesystem::path(prefix) / "share/traverse/runtime-manifest.json");
    if (!file) {
        result["error"] = "Private runtime manifest is missing";
        return false;
    }
    auto manifest = json::parse(file);
    for (const auto &entry : manifest.value("dynamicProviderAssets", json::array())) {
        auto path = std::filesystem::path(entry.get<std::string>());
        if (path.is_absolute() || path.string().find("..") != std::string::npos ||
            !std::filesystem::is_regular_file(std::filesystem::path(prefix) / path)) {
            result["error"] = "Private crypto provider asset is missing: " + path.string();
            return false;
        }
    }
    return true;
}

static bool media_roundtrip(json &result) {
    unsigned char bytes[30];
    if (RAND_bytes(bytes, sizeof(bytes)) != 1) {
        result["error"] = "Crypto random initialization failed";
        return false;
    }
    auto *key = gst_buffer_new_allocate(nullptr, sizeof(bytes), nullptr);
    gst_buffer_fill(key, 0, bytes, sizeof(bytes));
    GError *error = nullptr;
    auto *pipeline = gst_parse_launch(
        "videotestsrc num-buffers=3 ! video/x-raw,width=64,height=48,framerate=30/1 ! "
        "videoconvert ! video/x-raw,format=I420 ! vp8enc deadline=1 ! rtpvp8pay pt=96 ! "
        "srtpenc name=encrypt ! srtpdec name=decrypt ! rtpvp8depay ! vp8dec ! "
        "fakesink name=decoded sync=false signal-handoffs=true",
        &error);
    if (error || !pipeline) {
        result["error"] = error ? error->message : "Cannot create synthetic media pipeline";
        if (error)
            g_error_free(error);
        if (pipeline)
            gst_object_unref(pipeline);
        gst_buffer_unref(key);
        return false;
    }
    auto *encoder = gst_bin_get_by_name(GST_BIN(pipeline), "encrypt");
    auto *decoder = gst_bin_get_by_name(GST_BIN(pipeline), "decrypt");
    auto *sink = gst_bin_get_by_name(GST_BIN(pipeline), "decoded");
    g_object_set(encoder, "key", key, nullptr);
    g_signal_connect(
        decoder, "request-key", G_CALLBACK(+[](GstElement *, guint, gpointer data) -> GstCaps * {
            return gst_caps_new_simple("application/x-srtp", "srtp-key", GST_TYPE_BUFFER, data,
                                       "srtp-cipher", G_TYPE_STRING, "aes-128-icm", "srtp-auth",
                                       G_TYPE_STRING, "hmac-sha1-80", "srtcp-cipher", G_TYPE_STRING,
                                       "aes-128-icm", "srtcp-auth", G_TYPE_STRING, "hmac-sha1-80",
                                       nullptr);
        }),
        key);
    std::atomic<unsigned> frames{0};
    g_signal_connect(sink, "handoff",
                     G_CALLBACK(+[](GstElement *, GstBuffer *, GstPad *, gpointer data) {
                         ++*static_cast<std::atomic<unsigned> *>(data);
                     }),
                     &frames);
    auto *bus = gst_element_get_bus(pipeline);
    bool ok = gst_element_set_state(pipeline, GST_STATE_PLAYING) != GST_STATE_CHANGE_FAILURE;
    GstMessage *message = ok ? gst_bus_timed_pop_filtered(
                                   bus, 10 * GST_SECOND,
                                   static_cast<GstMessageType>(GST_MESSAGE_ERROR | GST_MESSAGE_EOS))
                             : nullptr;
    if (message && GST_MESSAGE_TYPE(message) == GST_MESSAGE_ERROR) {
        gst_message_parse_error(message, &error, nullptr);
        result["error"] = error ? error->message : "Encrypted media pipeline failed";
        if (error)
            g_error_free(error);
    }
    ok = message && GST_MESSAGE_TYPE(message) == GST_MESSAGE_EOS;
    gst_element_set_state(pipeline, GST_STATE_NULL);
    result["encryptedDecodedFrames"] = frames.load();
    ok = ok && frames == 3;
    if (!ok && !result.contains("error"))
        result["error"] = "Synthetic encrypted video did not finish decoding";
    if (message)
        gst_message_unref(message);
    gst_object_unref(bus);
    gst_object_unref(encoder);
    gst_object_unref(decoder);
    gst_object_unref(sink);
    gst_object_unref(pipeline);
    gst_buffer_unref(key);
    return ok;
}

int main(int argc, char **argv) {
    json result = {{"plugins", json::object()}};
    try {
        if (!provider_assets(result)) {
            result["ok"] = false;
            std::cout << result.dump(2) << '\n';
            return 1;
        }
        gst_init(&argc, &argv);
        result["gstreamer"] = gst_version_string();
        bool ok = true;
        for (const char *name :
             {"ximagesrc", "videoconvert", "unixfdsink", "unixfdsrc", "vp8enc", "rtpvp8pay",
              "webrtcbin", "nicesrc", "dtlsenc", "srtpenc", "sctpenc"}) {
            auto *factory = gst_element_factory_find(name);
            result["plugins"][name] = factory != nullptr;
            ok = ok && factory;
            if (factory)
                gst_object_unref(factory);
        }
        auto crypto = srtp_init();
        result["srtpInitialization"] = static_cast<int>(crypto);
        ok = ok && crypto == srtp_err_status_ok;
        if (ok)
            ok = media_roundtrip(result);
        else
            result["error"] = "Media factories or SRTP crypto initialization failed";
        result["ok"] = ok;
        std::cout << result.dump(2) << '\n';
        return ok ? 0 : 1;
    } catch (const std::exception &error) {
        result["ok"] = false;
        result["error"] = error.what();
        std::cout << result.dump(2) << '\n';
        return 1;
    }
}
