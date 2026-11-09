#include "common.hpp"
#include "endpoint_settings.hpp"
#include "child.hpp"
#include "standalone.hpp"
#include <fcntl.h>
#include <sys/file.h>

class OwnerLock {
    int fd = -1;

  public:
    explicit OwnerLock(const std::filesystem::path &directory) {
        std::filesystem::create_directories(directory);
        struct stat st{};
        if (lstat(directory.c_str(), &st) || !S_ISDIR(st.st_mode) || st.st_uid != getuid() ||
            (st.st_mode & 0077))
            throw std::runtime_error("Traverse runtime directory must be owned by you and private");
        fd = open((directory / "launcher.lock").c_str(), O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW,
                  0600);
        if (fd < 0 || flock(fd, LOCK_EX | LOCK_NB)) {
            if (fd >= 0)
                close(fd);
            fd = -1;
            throw std::runtime_error(
                "Traverse is already running or its owner lock is unavailable");
        }
    }
    ~OwnerLock() {
        if (fd >= 0)
            close(fd);
    }
};

int main(int argc, char **argv) {
    try {
        Args args(argc, argv);
        auto binary_dir = std::filesystem::canonical("/proc/self/exe").parent_path();
        if (args.has("--turn-child")) {
            guard_supervisor(args);
            traverse::turn_child(args.get("--turn-child"), binary_dir);
        }
        if (args.has("--help")) {
            std::cout
                << "Usage: traverse [--config FILE] [--check-config]\n"
                << "Run as the owner of an existing X11 desktop. Configure your self-hosted domain, "
                   "certificate/key and optional port first.\n";
            return 0;
        }
        const char *home = getenv("HOME");
        const char *config_home = getenv("XDG_CONFIG_HOME");
        if (!home && !config_home && !args.has("--config"))
            throw std::runtime_error("Set HOME, XDG_CONFIG_HOME or --config");
        auto config_path =
            args.get("--config",
                     (std::filesystem::path(
                          config_home ? config_home : std::string(home ? home : "") + "/.config") /
                      "traverse/config.json")
                         .string());
        std::ifstream file(config_path);
        if (!file)
            throw std::runtime_error("Create " + config_path +
                                     " from config.example.json, or pass --config FILE");
        auto config = json::parse(file);
        auto settings = traverse::EndpointSettings::parse(
            config, getenv("DISPLAY") ? getenv("DISPLAY") : "",
            std::filesystem::absolute(config_path).parent_path().string());
        const auto &origin = settings.origin;
        const auto &cert = settings.certificate;
        const auto &key = settings.private_key;
        const auto &display = settings.display;
        const auto &address = settings.listen_address;
        const auto port = settings.port;
        const auto media_port = settings.media_port;
        if (args.has("--check-config")) {
            std::cout << "Configuration valid; no screen capture or listener started\n";
            return 0;
        }
        if (display.empty())
            throw std::runtime_error("An existing X11 DISPLAY is required");
        umask(0077);
        auto directory = std::filesystem::path(default_socket()).parent_path();
        if (const char *runtime = getenv("XDG_RUNTIME_DIR"))
            directory = std::filesystem::path(runtime) / "traverse";
        directory = std::filesystem::absolute(directory);
        OwnerLock owner(directory);
        auto socket = (directory / "adapter.sock").string();
        Ipc ipc(socket);
        bool already_running = false;
        try {
            ipc.call("/state");
            already_running = true;
        } catch (...) {
        }
        if (already_running)
            throw std::runtime_error(
                "An adapter already owns this desktop; no existing process was changed");
        std::signal(SIGINT, signal_stop);
        std::signal(SIGTERM, signal_stop);
        std::signal(SIGPIPE, SIG_IGN);
        auto prefix = binary_dir.parent_path().parent_path();
        if (settings.mode == traverse::EndpointMode::Standalone)
            return traverse::standalone(settings, binary_dir, prefix, directory);
        Child adapter(binary_dir / "traverse-adapter", {"--display", display, "--socket", socket});
        bool ready = false;
        auto deadline = Clock::now() + std::chrono::seconds(15);
        while (!stopping && Clock::now() < deadline) {
            adapter.check();
            try {
                ipc.call("/state");
                ready = true;
                break;
            } catch (...) {
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        if (!ready)
            throw std::runtime_error("Desktop adapter did not become ready");
        Child service(binary_dir / "traverse-service",
                      {"--socket", socket, "--web", (prefix / "share/traverse/web").string(),
                       "--origin", origin, "--cert", cert, "--key", key, "--port",
                       std::to_string(port), "--udp-port", std::to_string(media_port), "--host",
                       address});
        std::cout << "Traverse URL: " << origin << "\nExternal reachability is not yet verified. "
                  << "Use the local pairing dialog to connect; press Ctrl+C to stop.\n"
                  << std::flush;
        while (!stopping) {
            adapter.check();
            service.check();
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        return 0;
    } catch (const std::exception &error) {
        std::cerr << "Traverse: " << error.what() << '\n';
        return 1;
    }
}
