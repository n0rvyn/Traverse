#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <gst/gst.h>
#include <iostream>
#include <nlohmann/json.hpp>
#include <openssl/rand.h>
#include <poll.h>
#include <spawn.h>
#include <srtp2/srtp.h>
#include <sys/wait.h>
#include <unistd.h>
using json = nlohmann::json;
extern char **environ;

static bool turn_version(const std::filesystem::path &binary, const std::string &expected,
                         json &result) {
    int descriptors[2];
    if (pipe2(descriptors, O_CLOEXEC | O_NONBLOCK))
        throw std::runtime_error("Cannot create runtime check pipe");
    // Closed standard streams must not collide with the child's dup2/close actions.
    int pipe[2] = {fcntl(descriptors[0], F_DUPFD_CLOEXEC, 3),
                   fcntl(descriptors[1], F_DUPFD_CLOEXEC, 3)};
    close(descriptors[0]);
    close(descriptors[1]);
    if (pipe[0] < 0 || pipe[1] < 0) {
        if (pipe[0] >= 0) close(pipe[0]);
        if (pipe[1] >= 0) close(pipe[1]);
        throw std::runtime_error("Cannot reserve runtime check descriptors");
    }
    posix_spawn_file_actions_t actions;
    int action_error = posix_spawn_file_actions_init(&actions);
    if (action_error) {
        close(pipe[0]);
        close(pipe[1]);
        throw std::runtime_error("Cannot prepare runtime check child");
    }
    action_error = posix_spawn_file_actions_adddup2(&actions, pipe[1], STDOUT_FILENO);
    if (!action_error)
        action_error = posix_spawn_file_actions_adddup2(&actions, pipe[1], STDERR_FILENO);
    if (!action_error)
        action_error = posix_spawn_file_actions_addclose(&actions, pipe[0]);
    if (!action_error)
        action_error = posix_spawn_file_actions_addclose(&actions, pipe[1]);
    if (action_error) {
        posix_spawn_file_actions_destroy(&actions);
        close(pipe[0]);
        close(pipe[1]);
        throw std::runtime_error("Cannot prepare runtime check output");
    }
    auto path = binary.string();
    char option[] = "--version";
    char *arguments[] = {path.data(), option, nullptr};
    pid_t child = -1;
    int error = posix_spawn(&child, path.c_str(), &actions, nullptr, arguments, environ);
    posix_spawn_file_actions_destroy(&actions);
    close(pipe[1]);
    if (error) {
        close(pipe[0]);
        result["error"] = "Cannot execute bundled TURN server";
        return false;
    }
    std::string output;
    int status = 0;
    bool reaped = false, eof = false;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (std::chrono::steady_clock::now() < deadline) {
        pollfd item{pipe[0], POLLIN, 0};
        int ready = poll(&item, 1, 100);
        if (ready > 0) {
            char bytes[1024];
            ssize_t count;
            while ((count = read(pipe[0], bytes, sizeof(bytes))) > 0)
                output.append(bytes, count);
            if (count == 0)
                eof = true;
        } else if (ready < 0 && errno != EINTR)
            break;
        if (!reaped && waitpid(child, &status, WNOHANG) == child)
            reaped = true;
        if (reaped && eof)
            break;
    }
    close(pipe[0]);
    if (!reaped) {
        kill(child, SIGKILL);
        while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
        }
        result["error"] = "Bundled TURN version check did not finish";
        return false;
    }
    if (!eof) {
        result["error"] = "Bundled TURN version output did not close";
        return false;
    }
    auto first = output.find_first_not_of(" \r\n\t"), last = output.find_last_not_of(" \r\n\t");
    auto version =
        first == std::string::npos ? std::string{} : output.substr(first, last - first + 1);
    if (!WIFEXITED(status) || WEXITSTATUS(status) || version != expected) {
        result["error"] = "Bundled TURN server could not report its required version";
        return false;
    }
    result["turnServerVersion"] = version;
    return true;
}

static bool bundled_assets(json &result) {
    const char *prefix = getenv("TRAVERSE_RUNTIME_PREFIX");
    if (!prefix)
        return true; // Unbundled development builds still test the actual crypto path.
    std::ifstream file(std::filesystem::path(prefix) / "share/traverse/runtime-manifest.json");
    if (!file) {
        result["error"] = "Private runtime manifest is missing";
        return false;
    }
    auto manifest = json::parse(file);
    for (const auto &entry : manifest.value("runtime_executables", json::array())) {
        auto name = entry.get<std::string>();
        if (name.empty() || std::filesystem::path(name).filename() != name || name == "..")
            throw std::runtime_error("Invalid runtime executable name");
        auto path = std::filesystem::path(prefix) / "libexec" /
                    (name == "gst-plugin-scanner" ? "gstreamer-1.0" : "traverse") / name;
        if (!std::filesystem::is_regular_file(path) || access(path.c_str(), X_OK)) {
            result["error"] = "Private runtime executable is missing: " + name;
            return false;
        }
    }
    for (const auto &entry : manifest.value("dynamicProviderAssets", json::array())) {
        auto path = std::filesystem::path(entry.get<std::string>());
        if (path.is_absolute() || path.string().find("..") != std::string::npos ||
            !std::filesystem::is_regular_file(std::filesystem::path(prefix) / path)) {
            result["error"] = "Private crypto provider asset is missing: " + path.string();
            return false;
        }
    }
    for (const auto &source : manifest.at("sources")) {
        if (source.at("name") == "coturn" &&
            !turn_version(std::filesystem::path(prefix) / "libexec/traverse/turnserver",
                          source.at("version").get<std::string>(), result))
            return false;
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
        if (!bundled_assets(result)) {
            result["ok"] = false;
            std::cout << result.dump(2) << '\n';
            return 1;
        }
        gst_init(&argc, &argv);
        result["gstreamer"] = gst_version_string();
        bool ok = true;
        for (const char *name :
             {"ximagesrc", "videoconvert", "unixfdsink", "unixfdsrc", "vp8enc", "rtpvp8pay",
              "rtprtxsend", "rtprtxreceive", "webrtcbin", "nicesrc", "dtlsenc", "srtpenc",
              "sctpenc"}) {
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
