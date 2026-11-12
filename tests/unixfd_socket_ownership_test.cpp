#include <gst/gst.h>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <grp.h>
#include <iostream>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>
namespace fs = std::filesystem;
static void require(bool value, const char *message) { if (!value) throw std::runtime_error(message); }
struct Pipeline {
    GstElement *value = gst_pipeline_new(nullptr);
    ~Pipeline() { stop(); }
    void stop() { if (value) { gst_element_set_state(value, GST_STATE_NULL); gst_object_unref(value); value = nullptr; } }
    GstElement *add(const char *name) {
        auto *element = gst_element_factory_make(name, nullptr);
        require(element, "Actual synthetic source/Unix-FD sink unavailable");
        gst_bin_add(GST_BIN(value), element); return element;
    }
    void start(const fs::path &path) {
        auto *source = add("videotestsrc"), *sink = add("unixfdsink");
        g_object_set(source, "is-live", TRUE, nullptr);
        g_object_set(sink, "socket-path", path.c_str(), "wait-for-connection", FALSE, "sync", FALSE, nullptr);
        require(gst_element_link(source, sink), "Actual synthetic transport link failed");
        require(gst_element_set_state(value, GST_STATE_PLAYING) != GST_STATE_CHANGE_FAILURE, "Transport did not start");
        auto end = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        struct stat info{};
        while (lstat(path.c_str(), &info) || !S_ISSOCK(info.st_mode)) {
            require(std::chrono::steady_clock::now() < end, "Actual transport never bound its socket");
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }
};
int main(int argc, char **argv) {
    if (!geteuid() && (setgroups(0, nullptr) || setgid(65534) || setuid(65534))) return 1;
    gst_init(&argc, &argv);
    char pattern[] = "/tmp/unixfd-owner-XXXXXX";
    const char *created = mkdtemp(pattern);
    if (!created) return 1;
    fs::path root(created), path = root / "f";
    int replacement = -1;
    try {
        { Pipeline pipeline; pipeline.start(path); pipeline.stop(); }
        require(!fs::exists(path), "Normal Stop did not remove the owned socket");
        {
            Pipeline pipeline; pipeline.start(path);
            fs::rename(path, root / "moved-file-socket");
            std::ofstream(path) << "preserve replacement\n";
            pipeline.stop();
            require(fs::exists(path), "Stop deleted a replacement regular file");
            std::ifstream input(path); std::string content; std::getline(input, content);
            require(content == "preserve replacement", "Stop changed replacement file contents");
        }
        fs::remove(path);
        {
            Pipeline pipeline; pipeline.start(path);
            fs::rename(path, root / "moved-listener");
            replacement = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
            require(replacement >= 0, "Replacement test socket unavailable");
            sockaddr_un address{}; address.sun_family = AF_UNIX;
            require(path.string().size() < sizeof(address.sun_path), "Test path too long");
            std::strcpy(address.sun_path, path.c_str());
            require(!bind(replacement, reinterpret_cast<sockaddr *>(&address), sizeof(address)) && !listen(replacement, 1), "Replacement listener failed");
            pipeline.stop();
            require(fs::is_socket(path), "Stop deleted a replacement socket");
            int client = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
            require(client >= 0, "Replacement connection unavailable");
            int connected = connect(client, reinterpret_cast<sockaddr *>(&address), sizeof(address));
            close(client); require(!connected, "Replacement listener stopped accepting connections");
        }
        close(replacement); replacement = -1;
        fs::remove_all(root);
        std::cout << "Actual transport retires owned sockets and preserves replacement files/listeners\n";
        return 0;
    } catch (const std::exception &error) {
        if (replacement >= 0) close(replacement);
        fs::remove_all(root); std::cerr << error.what() << '\n'; return 1;
    }
}
