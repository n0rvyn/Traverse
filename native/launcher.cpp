#include "common.hpp"
#include <fcntl.h>
#include <regex>
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

static int config_port(const json &config, const char *key, int fallback) {
    if (!config.contains(key))
        return fallback;
    if (!config[key].is_number_integer())
        throw std::runtime_error(std::string(key) + " must be an integer");
    if (config[key].is_number_unsigned() && config[key].get<unsigned long long>() > 65535)
        throw std::runtime_error(std::string(key) + " is out of range");
    auto port = config[key].get<long long>();
    if (port < 1 || port > 65535)
        throw std::runtime_error(std::string(key) + " must be between 1 and 65535");
    return static_cast<int>(port);
}

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
        if (!config.is_object())
            throw std::runtime_error("Configuration must be a JSON object");
        const std::vector<std::string> fields = {"origin",       "certificate", "privateKey",
                                                 "display",      "httpsPort",   "mediaPort",
                                                 "listenAddress"};
        for (auto it = config.begin(); it != config.end(); ++it)
            if (std::find(fields.begin(), fields.end(), it.key()) == fields.end())
                throw std::runtime_error("Unknown configuration field: " + it.key());
        auto origin = config.at("origin").get<std::string>();
        if (origin.rfind("https://", 0) || origin.find_first_of("\r\n\t ") != std::string::npos ||
            origin.find('/', 8) != std::string::npos || origin.find('@') != std::string::npos ||
            origin.find('?') != std::string::npos || origin.find('#') != std::string::npos ||
            origin.size() <= 8)
            throw std::runtime_error(
                "origin must be an HTTPS origin without a path or credentials");
        auto cert = config.at("certificate").get<std::string>();
        auto key = config.at("privateKey").get<std::string>();
        if (cert.empty() || key.empty())
            throw std::runtime_error("certificate and privateKey are required");
        int port = config_port(config, "httpsPort", 8443);
        int media_port = config_port(config, "mediaPort", 50000);
        if (port == media_port)
            throw std::runtime_error("HTTPS and passive ICE-TCP currently need separate TCP ports");
        std::smatch origin_parts;
        if (!std::regex_match(
                origin, origin_parts,
                std::regex(
                    R"(^https://(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9][A-Za-z0-9.-]*)(?::([0-9]+))?$)")))
            throw std::runtime_error("Invalid HTTPS origin hostname/port");
        auto public_port = origin_parts[2].matched ? std::stoull(origin_parts[2].str()) : 443;
        if (public_port != static_cast<unsigned>(port))
            throw std::runtime_error("Standalone HTTPS origin port must match httpsPort");
        auto display =
            config.value("display", std::string(getenv("DISPLAY") ? getenv("DISPLAY") : ""));
        auto address = config.value("listenAddress", std::string("0.0.0.0"));
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
