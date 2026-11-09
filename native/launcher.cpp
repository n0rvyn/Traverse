#include "common.hpp"
#include "endpoint_settings.hpp"
#include <fcntl.h>
#include <spawn.h>
#include <sys/file.h>
#include <sys/wait.h>
extern char **environ;

// The launcher supervises only children it spawned; no PID-file signalling.
class Child {
    pid_t pid = -1;
    std::string name;

  public:
    Child(const std::filesystem::path &binary, std::vector<std::string> arguments)
        : name(binary.filename()) {
        arguments.insert(arguments.begin(), binary.string());
        arguments.push_back("--supervisor-pid");
        arguments.push_back(std::to_string(getpid()));
        std::vector<char *> argv;
        for (auto &argument : arguments)
            argv.push_back(argument.data());
        argv.push_back(nullptr);
        int result = posix_spawn(&pid, binary.c_str(), nullptr, nullptr, argv.data(), environ);
        if (result) {
            pid = -1;
            throw std::runtime_error("Cannot start " + name + ": " + std::strerror(result));
        }
    }
    Child(const Child &) = delete;
    Child &operator=(const Child &) = delete;
    void check() {
        int status;
        pid_t result = waitpid(pid, &status, WNOHANG);
        if (result == pid) {
            pid = -1;
            throw std::runtime_error(name + " exited; sharing has stopped");
        }
        if (result < 0 && errno != EINTR)
            throw std::runtime_error("Cannot monitor " + name);
    }
    ~Child() {
        if (pid > 0) {
            kill(pid, SIGTERM);
            while (waitpid(pid, nullptr, 0) < 0 && errno == EINTR) {
            }
        }
    }
};

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
        if (args.has("--help")) {
            std::cout
                << "Usage: traverse [--config FILE] [--check-config]\n"
                << "Run as the owner of an existing X11 desktop. Configure your HTTPS origin, "
                   "certificate and private key first.\n";
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
        if (settings.mode == traverse::EndpointMode::Standalone)
            throw std::runtime_error("Standalone runtime integration is not built yet");
        if (display.empty())
            throw std::runtime_error("An existing X11 DISPLAY is required");
        umask(0077);
        auto directory = std::filesystem::path(default_socket()).parent_path();
        if (const char *runtime = getenv("XDG_RUNTIME_DIR"))
            directory = std::filesystem::path(runtime) / "traverse";
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
        auto binary_dir = std::filesystem::canonical("/proc/self/exe").parent_path();
        auto prefix = binary_dir.parent_path().parent_path();
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
