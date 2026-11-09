#include "standalone.hpp"
#include "child.hpp"
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <openssl/ssl.h>
#include <set>

namespace traverse {
namespace {
class PrivateFiles {
  public:
    std::filesystem::path directory;
    explicit PrivateFiles(const std::filesystem::path &runtime)
        : directory(runtime / ("instance-" + random_secret(16))) {
        if (!std::filesystem::create_directory(directory))
            throw std::runtime_error("Cannot create private sharing instance");
    }
    ~PrivateFiles() {
        std::error_code ignored;
        std::filesystem::remove_all(directory, ignored);
    }
    void write(const char *name, const std::string &contents) {
        auto path = directory / name;
        int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (fd < 0) throw std::runtime_error("Cannot create private sharing configuration");
        size_t offset = 0;
        while (offset < contents.size()) {
            auto count = ::write(fd, contents.data() + offset, contents.size() - offset);
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) {
                close(fd);
                throw std::runtime_error("Cannot write private sharing configuration");
            }
            offset += count;
        }
        if (close(fd)) throw std::runtime_error("Cannot close private sharing configuration");
    }
};
class Reservation {
    int fd = -1;
  public:
    unsigned short port;
    Reservation() {
        fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0) throw std::runtime_error("Cannot reserve private backend port");
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        socklen_t size = sizeof(address);
        if (bind(fd, reinterpret_cast<sockaddr *>(&address), size) ||
            getsockname(fd, reinterpret_cast<sockaddr *>(&address), &size)) {
            close(fd);fd = -1;
            throw std::runtime_error("Cannot reserve private backend port");
        }
        port = ntohs(address.sin_port);
    }
    void release() { if (fd >= 0) { close(fd);fd = -1; } }
    ~Reservation() { release(); }
};
class Sharing {
    Ipc ipc;
  public:
    std::unique_ptr<Child> adapter, turn, service, frontend;
    bool owns_adapter = false;
    explicit Sharing(const std::string &socket) : ipc(socket) {}
    void check() {
        for (auto *child : {adapter.get(), turn.get(), service.get(), frontend.get()})
            if (child) child->check();
    }
    ~Sharing() {
        // Release held input before any potentially blocking network teardown.
        if (owns_adapter && adapter && adapter->id() > 0) {
            try {
                if (ipc.call("/state").value("pid", pid_t{-1}) == adapter->id()) {
                    json empty = json::object();
                    ipc.call("/revoke", &empty);
                }
            } catch (...) {}
        }
        if (adapter) adapter->stop();
        if (frontend) frontend->stop();
        if (service) service->stop();
        if (turn) turn->stop();
    }
};
std::set<std::string> relay_addresses() {
    ifaddrs *list = nullptr;
    if (getifaddrs(&list)) throw std::runtime_error("Cannot inspect local relay addresses");
    std::unique_ptr<ifaddrs, decltype(&freeifaddrs)> owned(list, freeifaddrs);
    std::set<std::string> addresses;
    for (auto *item = list; item; item = item->ifa_next) {
        if (!item->ifa_addr || !(item->ifa_flags & IFF_UP) || (item->ifa_flags & IFF_LOOPBACK))
            continue;
        char text[INET6_ADDRSTRLEN];
        if (item->ifa_addr->sa_family == AF_INET) {
            auto address = reinterpret_cast<sockaddr_in *>(item->ifa_addr)->sin_addr;
            auto host = ntohl(address.s_addr);
            if ((host >> 24) == 127 || (host >> 16) == 0xa9fe || (host >> 24) == 0 ||
                (host >> 28) >= 14) continue;
            if (inet_ntop(AF_INET, &address, text, sizeof(text))) addresses.insert(text);
        } else if (item->ifa_addr->sa_family == AF_INET6) {
            auto address = reinterpret_cast<sockaddr_in6 *>(item->ifa_addr)->sin6_addr;
            if (IN6_IS_ADDR_LINKLOCAL(&address) || IN6_IS_ADDR_MULTICAST(&address) ||
                IN6_IS_ADDR_UNSPECIFIED(&address) || IN6_IS_ADDR_LOOPBACK(&address) ||
                IN6_IS_ADDR_V4MAPPED(&address)) continue;
            if (inet_ntop(AF_INET6, &address, text, sizeof(text))) addresses.insert(text);
        }
    }
    if (addresses.empty()) throw std::runtime_error("No eligible local relay interface address");
    return addresses;
}
bool owns_listener(pid_t pid, unsigned short port) {
    std::set<std::string> inodes;
    for (const auto &entry : std::filesystem::directory_iterator(
             "/proc/" + std::to_string(pid) + "/fd")) {
        std::error_code error;
        auto link = std::filesystem::read_symlink(entry.path(), error).string();
        if (!error && link.rfind("socket:[", 0) == 0 && link.back() == ']')
            inodes.insert(link.substr(8, link.size() - 9));
    }
    char endpoint[32];
    std::snprintf(endpoint, sizeof(endpoint), "0100007F:%04X", port);
    std::ifstream sockets("/proc/net/tcp");
    if (!sockets) throw std::runtime_error("Cannot inspect private TURN listener");
    for (std::string line; std::getline(sockets, line);) {
        std::istringstream input(line);
        std::vector<std::string> fields;
        for (std::string field; input >> field;) fields.push_back(field);
        if (fields.size() >= 10 && fields[1] == endpoint && fields[3] == "0A" &&
            inodes.count(fields[9])) return true;
    }
    return false;
}
bool https_ready(const EndpointSettings &settings) {
    auto host = settings.listen_address;
    if (host == "0.0.0.0") host = "127.0.0.1";
    if (host == "::") host = "::1";
    sockaddr_storage address{};
    auto *v4 = reinterpret_cast<sockaddr_in *>(&address);
    auto *v6 = reinterpret_cast<sockaddr_in6 *>(&address);
    int family = AF_INET;
    socklen_t size = sizeof(*v4);
    if (inet_pton(AF_INET, host.c_str(), &v4->sin_addr) == 1) {
        v4->sin_family = AF_INET;v4->sin_port = htons(settings.port);
    } else {
        family = AF_INET6;size = sizeof(*v6);
        v6->sin6_family = AF_INET6;v6->sin6_port = htons(settings.port);
        if (inet_pton(AF_INET6, host.c_str(), &v6->sin6_addr) != 1)
            throw std::runtime_error("Invalid local HTTPS probe address");
    }
    int fd = socket(family, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) throw std::runtime_error("Cannot probe local HTTPS listener");
    struct Close { int fd;~Close() { close(fd); } } owned{fd};
    timeval timeout{1, 0};
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)))
        throw std::runtime_error("Cannot bound local HTTPS probe");
    if (connect(fd, reinterpret_cast<sockaddr *>(&address), size)) return false;
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> context(SSL_CTX_new(TLS_client_method()), SSL_CTX_free);
    if (!context || !SSL_CTX_set_default_verify_paths(context.get()))
        throw std::runtime_error("Cannot load system HTTPS trust store");
    SSL_CTX_set_verify(context.get(), SSL_VERIFY_PEER, nullptr);
    std::unique_ptr<SSL, decltype(&SSL_free)> tls(SSL_new(context.get()), SSL_free);
    if (!tls) throw std::runtime_error("Cannot create HTTPS verification session");
    in_addr ip4{};in6_addr ip6{};
    if (inet_pton(AF_INET, settings.domain.c_str(), &ip4) == 1 ||
        inet_pton(AF_INET6, settings.domain.c_str(), &ip6) == 1) {
        if (!X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(tls.get()), settings.domain.c_str()))
            throw std::runtime_error("Cannot set HTTPS IP verification");
    } else if (!SSL_set1_host(tls.get(), settings.domain.c_str()) ||
               !SSL_set_tlsext_host_name(tls.get(), settings.domain.c_str()))
        throw std::runtime_error("Cannot set HTTPS hostname verification");
    if (!SSL_set_fd(tls.get(), fd) || SSL_connect(tls.get()) != 1) {
        if (SSL_get_verify_result(tls.get()) != X509_V_OK)
            throw std::runtime_error("HTTPS certificate is not trusted for the configured domain");
        return false;
    }
    auto request = "GET " + settings.base_path + " HTTP/1.1\r\nHost: " +
                   settings.origin.substr(8) + "\r\nConnection: close\r\n\r\n";
    if (SSL_write(tls.get(), request.data(), request.size()) != static_cast<int>(request.size()))
        return false;
    std::string response;
    char bytes[1024];
    while (response.find("\r\n") == std::string::npos) {
        int count = SSL_read(tls.get(), bytes, sizeof(bytes));
        if (count <= 0) return false;
        response.append(bytes, count);
    }
    return response.rfind("HTTP/1.1 200 ", 0) == 0;
}
} // namespace

void turn_child(const std::filesystem::path &configuration,
                const std::filesystem::path &binary_directory) {
    if (!configuration.is_absolute()) throw std::runtime_error("Private TURN config must be absolute");
    if (chdir(configuration.parent_path().c_str()))
        throw std::runtime_error("Cannot enter private TURN runtime directory");
    auto binary = (binary_directory / "turnserver").string();
    execl(binary.c_str(), "turnserver", "-c", configuration.c_str(), nullptr);
    throw std::runtime_error("Cannot execute private TURN server");
}

int standalone(const EndpointSettings &settings, const std::filesystem::path &binary_directory,
               const std::filesystem::path &prefix, const std::filesystem::path &runtime) {
    PrivateFiles files(runtime);
    auto socket = (runtime / "adapter.sock").string();
    Ipc ipc(socket);
    Sharing children(socket);
    Reservation http, turn;
    auto addresses = relay_addresses();
    auto username = "traverse-" + random_secret(16), password = random_secret(32);
    std::string config = "listening-ip=127.0.0.1\nlistening-port=" + std::to_string(turn.port) +
        "\nno-udp\nno-tls\ndtls=false\ncli=false\nweb-admin=false\nno-tcp-relay\n"
        "lt-cred-mech\nrealm=" + settings.domain + "\nuser=" + username + ":" + password +
        "\ndenied-peer-ip=0.0.0.0-255.255.255.255\n"
        "denied-peer-ip=::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff\n"
        "no-multicast-peers\npidfile=turn.pid\nuserdb=turn.sqlite\nlog-file=turn.log\nsimple-log\nrelay-threads=1\n";
    for (const auto &address : addresses)
        config += "relay-ip=" + address + "\nallowed-peer-ip=" + address + "\n";
    files.write("turn.conf", config);
    json ice = {{"iceServers", json::array({{{"urls", settings.turns_url()},
                                            {"username", username}, {"credential", password}}})}};
    files.write("ice.json", ice.dump());
    children.adapter = std::make_unique<Child>(binary_directory / "traverse-adapter",
        std::vector<std::string>{"--display", settings.display, "--socket", socket});
    auto deadline = Clock::now() + std::chrono::seconds(15);
    bool ready = false;
    while (!stopping && Clock::now() < deadline) {
        children.check();
        try {
            auto state = ipc.call("/state");
            if (state.value("pid", pid_t{-1}) != children.adapter->id())
                throw std::runtime_error("Another adapter owns this desktop");
            children.owns_adapter = true;
            ready = state.value("armed", false);
            break;
        } catch (const std::exception &) {
            if (children.owns_adapter) throw;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    if (!ready) throw std::runtime_error("Desktop adapter did not become ready");
    turn.release();
    children.turn = std::make_unique<Child>(binary_directory / "traverse-launcher",
        std::vector<std::string>{"--turn-child", (files.directory / "turn.conf").string()});
    deadline = Clock::now() + std::chrono::seconds(15);
    while (!stopping && !owns_listener(children.turn->id(), turn.port)) {
        children.check();
        if (Clock::now() >= deadline) throw std::runtime_error("Private TURN listener did not become ready");
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    auto start = [&](const char *role, const char *name, std::vector<std::string> args) {
        auto binary = binary_directory / name;
        if (settings.port < 1024) {
            binary = binary_directory / "traverse-bind-helper";
            args.insert(args.begin(), role);
        }
        return std::make_unique<Child>(binary, args, true);
    };
    http.release();
    children.service = start("service", "traverse-service",
        {"--internal-http", "--host", "127.0.0.1", "--port", std::to_string(http.port),
         "--origin", settings.origin, "--socket", socket, "--web", (prefix / "share/traverse/web").string(),
         "--base-path", settings.base_path, "--udp-port", std::to_string(settings.port), "--udp-only",
         "--check-udp-port", "--ice-config", (files.directory / "ice.json").string()});
    auto expected = "Internal HTTP backend for " + settings.origin +
                    (settings.base_path == "/" ? "" : settings.base_path);
    if (children.service->ready_line() != expected)
        throw std::runtime_error("Internal HTTP service readiness response invalid");
    children.frontend = start("frontend", "traverse-tls-frontend",
        {"--host", settings.listen_address, "--port", std::to_string(settings.port),
         "--http-port", std::to_string(http.port), "--turn-port", std::to_string(turn.port),
         "--cert", settings.certificate, "--key", settings.private_key});
    if (json::parse(children.frontend->ready_line()).value("port", 0) != settings.port)
        throw std::runtime_error("TLS listener readiness response invalid");
    deadline = Clock::now() + std::chrono::seconds(15);
    ready = false;
    while (!stopping && Clock::now() < deadline) {
        children.check();
        if (https_ready(settings)) { ready = true;break; }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    if (!ready) throw std::runtime_error("Local HTTPS endpoint did not become ready");
    std::cout << "Traverse URL: " << settings.public_url()
              << "\nLocal HTTPS verified. External reachability is not yet verified. "
                 "Use the local pairing dialog to connect; press Ctrl+C to stop.\n" << std::flush;
    while (!stopping) {
        children.check();
        auto state = ipc.call("/state");
        if (state.value("pid", pid_t{-1}) != children.adapter->id())
            throw std::runtime_error("Desktop adapter ownership changed");
        if (!state.value("armed", false)) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return 0;
}
} // namespace traverse
