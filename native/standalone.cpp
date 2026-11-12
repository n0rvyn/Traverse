#include "standalone.hpp"
#include "certificate_manager.hpp"
#include "child.hpp"
#include "host_channel.hpp"
#include "owner_state.hpp"
#include "private_socket_directory.hpp"
#include "readiness_manager.hpp"
#include "readiness_network.hpp"
#include "tls_certificate.hpp"
#include <arpa/inet.h>
#include <ctime>
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
        if (fd < 0)
            throw std::runtime_error("Cannot create private sharing configuration");
        size_t offset = 0;
        while (offset < contents.size()) {
            auto count = ::write(fd, contents.data() + offset, contents.size() - offset);
            if (count < 0 && errno == EINTR)
                continue;
            if (count <= 0) {
                close(fd);
                throw std::runtime_error("Cannot write private sharing configuration");
            }
            offset += count;
        }
        if (close(fd))
            throw std::runtime_error("Cannot close private sharing configuration");
    }
};
class Reservation {
    int fd = -1;

  public:
    unsigned short port;
    Reservation() {
        fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0)
            throw std::runtime_error("Cannot reserve private backend port");
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        socklen_t size = sizeof(address);
        if (bind(fd, reinterpret_cast<sockaddr *>(&address), size) ||
            getsockname(fd, reinterpret_cast<sockaddr *>(&address), &size)) {
            close(fd);
            fd = -1;
            throw std::runtime_error("Cannot reserve private backend port");
        }
        port = ntohs(address.sin_port);
    }
    void release() {
        if (fd >= 0) {
            close(fd);
            fd = -1;
        }
    }
    ~Reservation() {
        release();
    }
};
class Sharing {
    Ipc ipc;

  public:
    std::unique_ptr<Child> adapter, turn, service, frontend, validation;
    std::unique_ptr<CertificateManager> certificates;
    std::unique_ptr<ReadinessManager> readiness;
    std::unique_ptr<ReadinessNetwork> readiness_network;
    bool network_observation_healthy=true;
    bool owns_adapter = false;
    explicit Sharing(const std::string &socket) : ipc(socket) {}
    void check() {
        for (auto *child : {adapter.get(), turn.get(), service.get(), frontend.get()})
            if (child)
                child->check();
        if (validation) {
            try {
                validation->check();
            } catch (const std::exception &) {
                validation.reset();
                if (certificates)
                    certificates->validation_route(false);
            }
        }
    }
    ~Sharing() {
        // Release held input before any potentially blocking network teardown.
        if (owns_adapter && adapter && adapter->id() > 0) {
            try {
                if (ipc.call("/state").value("pid", pid_t{-1}) == adapter->id()) {
                    json empty = json::object();
                    ipc.call("/revoke", &empty);
                }
            } catch (...) {
            }
        }
        if (adapter)
            adapter->stop();
        readiness.reset();
        if (certificates)
            certificates->stop();
        if (validation)
            validation->stop();
        if (frontend)
            frontend->stop();
        if (service)
            service->stop();
        if (turn)
            turn->stop();
    }
};
class CertificateObserver {
    std::optional<TlsCertificateStatus> previous;
    std::string metadata_error;
    bool allow_unprovisioned;

  public:
    explicit CertificateObserver(bool automatic = false) : allow_unprovisioned(automatic) {}
    std::optional<TlsCertificateStatus> observe(const std::string &path, pid_t frontend) {
        try {
            auto current = read_tls_certificate_status(path, frontend, allow_unprovisioned);
            if (!metadata_error.empty())
                std::cerr << "Traverse certificate: status restored\n";
            metadata_error.clear();
            if (!current.available) {
                if (!previous || previous->available) {
                    auto now = std::time(nullptr);
                    auto reason = !current.revision                     ? "not provisioned"
                                  : now == static_cast<std::time_t>(-1) ? "unavailable"
                                  : now >= current.valid_until          ? "expired"
                                  : now < current.valid_from            ? "not yet valid"
                                                                        : "unavailable";
                    std::cerr << "Traverse certificate: " << reason
                              << "; new connections unavailable\n";
                }
            } else if (!previous || !previous->available) {
                std::cerr << "Traverse certificate: available\n";
            } else if (current.fingerprint != previous->fingerprint) {
                std::cerr << "Traverse certificate: renewed; sharing continues\n";
            } else if (current.error.empty() && !previous->error.empty()) {
                std::cerr << "Traverse certificate: renewal recovered; sharing continues\n";
            }
            if (!current.error.empty() && (!previous || current.error != previous->error))
                std::cerr << "Traverse certificate: "
                          << (current.revision ? "renewal rejected: " : "provisioning pending: ")
                          << current.error << '\n';
            previous = std::move(current);
            return previous;
        } catch (const std::exception &error) {
            if (metadata_error != error.what())
                std::cerr << "Traverse certificate: status unavailable: " << error.what() << '\n';
            metadata_error = error.what();
            return std::nullopt;
        }
    }
};
std::set<std::string> relay_addresses() {
    ifaddrs *list = nullptr;
    if (getifaddrs(&list))
        throw std::runtime_error("Cannot inspect local relay addresses");
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
                (host >> 28) >= 14)
                continue;
            if (inet_ntop(AF_INET, &address, text, sizeof(text)))
                addresses.insert(text);
        } else if (item->ifa_addr->sa_family == AF_INET6) {
            auto address = reinterpret_cast<sockaddr_in6 *>(item->ifa_addr)->sin6_addr;
            if (IN6_IS_ADDR_LINKLOCAL(&address) || IN6_IS_ADDR_MULTICAST(&address) ||
                IN6_IS_ADDR_UNSPECIFIED(&address) || IN6_IS_ADDR_LOOPBACK(&address) ||
                IN6_IS_ADDR_V4MAPPED(&address))
                continue;
            if (inet_ntop(AF_INET6, &address, text, sizeof(text)))
                addresses.insert(text);
        }
    }
    if (addresses.empty())
        throw std::runtime_error("No eligible local relay interface address");
    return addresses;
}
bool owns_listener(pid_t pid, unsigned short port) {
    std::set<std::string> inodes;
    for (const auto &entry :
         std::filesystem::directory_iterator("/proc/" + std::to_string(pid) + "/fd")) {
        std::error_code error;
        auto link = std::filesystem::read_symlink(entry.path(), error).string();
        if (!error && link.rfind("socket:[", 0) == 0 && link.back() == ']')
            inodes.insert(link.substr(8, link.size() - 9));
    }
    char endpoint[32];
    std::snprintf(endpoint, sizeof(endpoint), "0100007F:%04X", port);
    std::ifstream sockets("/proc/net/tcp");
    if (!sockets)
        throw std::runtime_error("Cannot inspect private TURN listener");
    for (std::string line; std::getline(sockets, line);) {
        std::istringstream input(line);
        std::vector<std::string> fields;
        for (std::string field; input >> field;)
            fields.push_back(field);
        if (fields.size() >= 10 && fields[1] == endpoint && fields[3] == "0A" &&
            inodes.count(fields[9]))
            return true;
    }
    return false;
}
bool https_ready(const EndpointSettings &settings) {
    auto host = settings.listen_address;
    if (host == "0.0.0.0")
        host = "127.0.0.1";
    if (host == "::")
        host = "::1";
    sockaddr_storage address{};
    auto *v4 = reinterpret_cast<sockaddr_in *>(&address);
    auto *v6 = reinterpret_cast<sockaddr_in6 *>(&address);
    int family = AF_INET;
    socklen_t size = sizeof(*v4);
    if (inet_pton(AF_INET, host.c_str(), &v4->sin_addr) == 1) {
        v4->sin_family = AF_INET;
        v4->sin_port = htons(settings.port);
    } else {
        family = AF_INET6;
        size = sizeof(*v6);
        v6->sin6_family = AF_INET6;
        v6->sin6_port = htons(settings.port);
        if (inet_pton(AF_INET6, host.c_str(), &v6->sin6_addr) != 1)
            throw std::runtime_error("Invalid local HTTPS probe address");
    }
    int fd = socket(family, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        throw std::runtime_error("Cannot probe local HTTPS listener");
    struct Close {
        int fd;
        ~Close() {
            close(fd);
        }
    } owned{fd};
    timeval timeout{1, 0};
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)))
        throw std::runtime_error("Cannot bound local HTTPS probe");
    if (connect(fd, reinterpret_cast<sockaddr *>(&address), size))
        return false;
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> context(SSL_CTX_new(TLS_client_method()),
                                                              SSL_CTX_free);
    bool custom_trust = settings.certificates.mode != CertificateMode::Supplied &&
                        !settings.certificates.certificate_trust_file.empty();
    if (!context ||
        (custom_trust ? SSL_CTX_load_verify_locations(
                            context.get(), settings.certificates.certificate_trust_file.c_str(),
                            nullptr) != 1
                      : SSL_CTX_set_default_verify_paths(context.get()) != 1))
        throw std::runtime_error("Cannot load system HTTPS trust store");
    SSL_CTX_set_verify(context.get(), SSL_VERIFY_PEER, nullptr);
    std::unique_ptr<SSL, decltype(&SSL_free)> tls(SSL_new(context.get()), SSL_free);
    if (!tls)
        throw std::runtime_error("Cannot create HTTPS verification session");
    in_addr ip4{};
    in6_addr ip6{};
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
    auto request = "GET " + settings.base_path + " HTTP/1.1\r\nHost: " + settings.origin.substr(8) +
                   "\r\nConnection: close\r\n\r\n";
    if (SSL_write(tls.get(), request.data(), request.size()) != static_cast<int>(request.size()))
        return false;
    std::string response;
    char bytes[1024];
    while (response.find("\r\n") == std::string::npos) {
        int count = SSL_read(tls.get(), bytes, sizeof(bytes));
        if (count <= 0)
            return false;
        response.append(bytes, count);
    }
    return response.rfind("HTTP/1.1 200 ", 0) == 0;
}
} // namespace

void turn_child(const std::filesystem::path &configuration,
                const std::filesystem::path &binary_directory) {
    if (!configuration.is_absolute())
        throw std::runtime_error("Private TURN config must be absolute");
    if (chdir(configuration.parent_path().c_str()))
        throw std::runtime_error("Cannot enter private TURN runtime directory");
    auto binary = (binary_directory / "turnserver").string();
    execl(binary.c_str(), "turnserver", "-c", configuration.c_str(), nullptr);
    throw std::runtime_error("Cannot execute private TURN server");
}

int standalone(const EndpointSettings &requested, const std::filesystem::path &binary_directory,
               const std::filesystem::path &prefix, const std::filesystem::path &runtime,
               HostSupervisor *owner) {
    auto settings = requested;
    PrivateFiles files(runtime);
    PrivateSocketDirectory sockets(runtime);
    auto socket = (runtime / "adapter.sock").string();
    Ipc ipc(socket);
    Sharing children(socket);
    const bool automatic = settings.certificates.mode == CertificateMode::Automatic;
    const bool local = settings.certificates.mode == CertificateMode::Local;
    const bool managed = automatic || local;
    HostSupervisor absent;
    auto &host = owner ? *owner : absent;
    bool service_ready = false, https_verified = false;
    struct OwnerBinding {
        HostSupervisor &host;
        ~OwnerBinding() {
            host.unbind();
        }
    } binding{host};
    if (host.enabled()) {
        host.bind(
            [&] {
                json state = {{"configuredUrl", settings.public_url()},
                              {"externalReachability", "unknown"},
                              {"localHttps", {{"status", https_verified ? "passed" : "pending"}}},
                              {"authority", {{"status", "unavailable"}}},
                              {"peer", {{"status", "unavailable"}}},
                              {"certificate", {{"status", "unknown"}}}};
                if (children.owns_adapter && children.adapter) {
                    try {
                        state["authority"] =
                            read_owned_state(socket, children.adapter->id(), "/owner/authority");
                    } catch (const std::exception &) {
                    }
                }
                if (service_ready && children.service) {
                    try {
                        state["peer"] = read_owner_state((sockets.directory / "s").string(),
                                                         children.service->id());
                    } catch (const std::exception &) {
                    }
                }
                if (children.certificates)
                    state["issuer"] = children.certificates->status();
                if(children.readiness) {
                    state["urlCheck"]=children.readiness->snapshot();
                    state["urlCheck"]["networkObservation"]=children.network_observation_healthy?"active":"unavailable";
                }
                if (children.frontend) {
                    try {
                        auto certificate = read_tls_certificate_status(
                            (files.directory / "tls-status.json").string(), children.frontend->id(),
                            managed);
                        state["certificate"] = {
                            {"status", certificate.available ? "passed" : "pending"},
                            {"available", certificate.available},
                            {"fingerprint", certificate.fingerprint},
                            {"revision", certificate.revision},
                            {"validUntil", certificate.valid_until},
                            {"reloadError", certificate.error}};
                        if (https_verified && !certificate.available)
                            state["localHttps"]["status"] = "unavailable";
                    } catch (const std::exception &) {
                        if (https_verified)
                            state["localHttps"]["status"] = "unknown";
                    }
                }
                return state;
            },
            [&] {
                if (!children.owns_adapter || !children.adapter)
                    return json{{"ok", false}, {"error", "not-ready"}};
                json empty = json::object();
                auto result =
                    owned_json_request(socket, children.adapter->id(), "/owner/new-code", &empty);
                if (result.first == 409)
                    return json{{"ok", false}, {"error", "paired-or-stopped"}};
                if (result.first != 200)
                    return json{{"ok", false}, {"error", "producer-unavailable"}};
                validate_owner_state(std::move(result.second), children.adapter->id());
                return json{{"ok", true}};
            },
            [&] {
                if(!children.readiness)return json{{"ok",false},{"error","not-configured"}};
                return children.readiness->start()?json{{"ok",true}}:json{{"ok",false},{"error","check-running"}};
            },
            [&] {
                if (!local || !https_verified || !children.certificates || !children.frontend || stopping)
                    return json{{"ok",false},{"error","not-ready"}};
                try {
                    return json{{"ok",true},{"publicCA",children.certificates->public_authority()}};
                } catch (const std::exception &) {
                    return json{{"ok",false},{"error","authority-unavailable"}};
                }
            });
    }
    auto pump_owner = [&] {
        if (host.pump())
            stopping = true;
    };
    host.stage("certificate-state");
    pump_owner();
    if (stopping)
        return 0;
    if (managed) {
        const char *data = getenv("XDG_DATA_HOME"), *home = getenv("HOME");
        if ((!data || !*data) && (!home || !*home))
            throw std::runtime_error("Managed certificates require an owner data directory");
        auto data_home =
            std::filesystem::path(data && *data ? data : std::string(home) + "/.local/share");
        if (!data_home.is_absolute())
            throw std::runtime_error("Owner data directory must be absolute");
        data_home = std::filesystem::weakly_canonical(data_home);
        // Keep broker sockets in the short private socket directory too.
        children.certificates = std::make_unique<CertificateManager>(
            settings.certificates, data_home.string(), binary_directory / "traverse-issuer",
            (sockets.directory / "v").string());
        settings.certificates.certificate = children.certificates->bundle();
        settings.certificates.private_key = children.certificates->bundle();
        settings.certificates.certificate_trust_file = children.certificates->trust_file();
        if (local) {
            host.stage("certificate", "waiting-certificate");
            while (!stopping && !children.certificates->application().available) {
                pump_owner();
                if (stopping)
                    return 0;
                children.certificates->tick();
                if (children.certificates->status().at("phase") == "failed")
                    throw std::runtime_error("Local certificate preparation failed");
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
            if (stopping)
                return 0;
        }
    }
    Reservation http, turn;
    auto addresses = relay_addresses();
    auto username = "traverse-" + random_secret(16), password = random_secret(32);
    std::string config = "listening-ip=127.0.0.1\nlistening-port=" + std::to_string(turn.port) +
                         "\nno-udp\nno-tls\ndtls=false\ncli=false\nweb-admin=false\nno-tcp-relay\n"
                         "lt-cred-mech\nrealm=" +
                         settings.domain + "\nuser=" + username + ":" + password +
                         "\ndenied-peer-ip=0.0.0.0-255.255.255.255\n"
                         "denied-peer-ip=::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff\n"
                         "no-multicast-peers\npidfile=turn.pid\nuserdb=turn.sqlite\nlog-file=turn."
                         "log\nsimple-log\nrelay-threads=1\n";
    for (const auto &address : addresses)
        config += "relay-ip=" + address + "\nallowed-peer-ip=" + address + "\n";
    files.write("turn.conf", config);
    json ice = {{"iceServers", json::array({{{"urls", settings.turns_url()},
                                             {"username", username},
                                             {"credential", password}}})}};
    files.write("ice.json", ice.dump());
    host.stage("adapter");
    pump_owner();
    if (stopping)
        return 0;
    children.adapter = std::make_unique<Child>(
        binary_directory / "traverse-adapter",
        std::vector<std::string>{"--display", settings.display, "--socket", socket});
    auto deadline = Clock::now() + std::chrono::seconds(15);
    bool ready = false;
    while (!stopping && Clock::now() < deadline) {
        pump_owner();
        if (stopping)
            break;
        children.check();
        try {
            auto state = ipc.call("/state");
            if (state.value("pid", pid_t{-1}) != children.adapter->id())
                throw std::runtime_error("Another adapter owns this desktop");
            children.owns_adapter = true;
            ready = state.value("armed", false);
            break;
        } catch (const std::exception &) {
            if (children.owns_adapter)
                throw;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    if (!ready)
        throw std::runtime_error("Desktop adapter did not become ready");
    host.stage("turn");
    pump_owner();
    if (stopping)
        return 0;
    turn.release();
    children.turn = std::make_unique<Child>(
        binary_directory / "traverse-launcher",
        std::vector<std::string>{"--turn-child", (files.directory / "turn.conf").string()});
    deadline = Clock::now() + std::chrono::seconds(15);
    while (!stopping && !owns_listener(children.turn->id(), turn.port)) {
        pump_owner();
        if (stopping)
            break;
        children.check();
        if (Clock::now() >= deadline)
            throw std::runtime_error("Private TURN listener did not become ready");
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    auto start = [&](const char *role, const char *name, std::vector<std::string> args,
                     unsigned short public_port) {
        pump_owner();
        if (stopping)
            throw std::runtime_error("Sharing stopped during local startup");
        auto binary = binary_directory / name;
        if (public_port < 1024) {
            binary = binary_directory / "traverse-bind-helper";
            args.insert(args.begin(), role);
        }
        return std::make_unique<Child>(binary, args, true);
    };
    host.stage("service");
    http.release();
    children.service = start("service", "traverse-service",
                             {"--internal-http",
                              "--host",
                              "127.0.0.1",
                              "--port",
                              std::to_string(http.port),
                              "--origin",
                              settings.origin,
                              "--socket",
                              socket,
                              "--web",
                              (prefix / "share/traverse/web").string(),
                              "--owner-socket",
                              (sockets.directory / "s").string(),
                              "--base-path",
                              settings.base_path,
                              "--udp-port",
                              std::to_string(settings.port),
                              "--udp-only",
                              "--check-udp-port",
                              "--ice-config",
                              (files.directory / "ice.json").string()},
                             settings.port);
    auto expected = "Internal HTTP backend for " + settings.origin +
                    (settings.base_path == "/" ? "" : settings.base_path);
    if (children.service->ready_line(pump_owner) != expected)
        throw std::runtime_error("Internal HTTP service readiness response invalid");
    read_owner_state((sockets.directory / "s").string(), children.service->id());
    service_ready = true;
    host.stage("tls");
    std::vector<std::string> frontend_arguments = {"--host",
                                                   settings.listen_address,
                                                   "--port",
                                                   std::to_string(settings.port),
                                                   "--http-port",
                                                   std::to_string(http.port),
                                                   "--turn-port",
                                                   std::to_string(turn.port),
                                                   "--cert",
                                                   settings.certificates.certificate,
                                                   "--key",
                                                   settings.certificates.private_key,
                                                   "--expected-domain",
                                                   settings.domain,
                                                   "--status-file",
                                                   (files.directory / "tls-status.json").string()};
    // The binding helper intentionally clears environment and changes cwd. Carry
    // only the caller's selected trust locations as explicit, absolute arguments.
    if (managed && !settings.certificates.certificate_trust_file.empty()) {
        frontend_arguments.insert(frontend_arguments.end(),
                                  {"--trust-file", settings.certificates.certificate_trust_file,
                                   "--trust-directory", ""});
    } else if (const char *file = getenv("SSL_CERT_FILE")) {
        frontend_arguments.insert(
            frontend_arguments.end(),
            {"--trust-file",
             *file ? std::filesystem::absolute(file).lexically_normal().string() : ""});
    }
    if (const char *directory = getenv("SSL_CERT_DIR");
        directory && !(managed && !settings.certificates.certificate_trust_file.empty())) {
        std::string resolved, paths(directory);
        size_t begin = 0;
        while (true) {
            auto end = paths.find(':', begin);
            auto path = paths.substr(begin, end == std::string::npos ? end : end - begin);
            if (!path.empty())
                resolved += std::filesystem::absolute(path).lexically_normal().string();
            if (end == std::string::npos)
                break;
            resolved += ':';
            begin = end + 1;
        }
        frontend_arguments.insert(frontend_arguments.end(), {"--trust-directory", resolved});
    }
    if (automatic)
        frontend_arguments.insert(
            frontend_arguments.end(),
            {"--acme-socket", settings.port == 443
                                  ? children.certificates->broker()
                                  : (sockets.directory / "a").string()});
    bool proof_only = automatic && !children.certificates->application().available;
    auto launch_frontend = [&](bool proof) {
        auto arguments = frontend_arguments;
        if (proof)
            arguments.insert(arguments.end(), {"--challenge-only", "true"});
        children.frontend = start("frontend", "traverse-tls-frontend", arguments, settings.port);
        if (json::parse(children.frontend->ready_line(pump_owner)).value("port", 0) !=
            settings.port)
            throw std::runtime_error("TLS listener readiness response invalid");
    };
    launch_frontend(proof_only);
    if (automatic) {
        bool validation_ready = settings.port == 443;
        if (settings.port != 443) {
            try {
                children.validation =
                    start("frontend", "traverse-tls-frontend",
                          {"--host", settings.listen_address, "--port", "443", "--challenge-only",
                           "true", "--expected-domain", settings.domain, "--acme-socket",
                           children.certificates->broker(), "--status-file",
                           (files.directory / "validation-status.json").string()},
                          443);
                if (json::parse(children.validation->ready_line(pump_owner)).value("port", 0) !=
                    443)
                    throw std::runtime_error("Validation listener readiness response invalid");
                auto status = read_tls_certificate_status(
                    (files.directory / "validation-status.json").string(),
                    children.validation->id(), true);
                if (status.available || status.revision)
                    throw std::runtime_error(
                        "Validation-only listener admitted application material");
                validation_ready = true;
            } catch (const std::exception &) {
                children.validation.reset();
                if (proof_only)
                    throw std::runtime_error("Standard certificate validation port443 is "
                                             "unavailable; no account or order started");
            }
        }
        children.certificates->validation_route(validation_ready);
    }
    CertificateObserver certificate_observer(managed);
    auto certificate_status = (files.directory / "tls-status.json").string();
    auto initial =
        read_tls_certificate_status(certificate_status, children.frontend->id(), proof_only);
    if (children.certificates)
        children.certificates->frontend(initial);
    certificate_observer.observe(certificate_status, children.frontend->id());
    auto owner_armed = [&] {
        auto state = ipc.call("/state");
        if (state.value("pid", pid_t{-1}) != children.adapter->id())
            throw std::runtime_error("Desktop adapter ownership changed");
        return state.value("armed", false);
    };
    // Local listener startup keeps its existing deadline; CA validation is an
    // owned asynchronous workflow and can remain pending beyond15seconds.
    if (proof_only)
        host.stage("certificate", "waiting-certificate");
    while (!stopping && proof_only) {
        pump_owner();
        if (stopping)
            break;
        children.check();
        if (!owner_armed())
            return 0;
        children.certificates->tick();
        if (children.certificates->application().available) {
            children.frontend.reset();
            pump_owner();
            if (stopping)
                return 0;
            launch_frontend(false);
            proof_only = false;
            children.certificates->frontend(
                read_tls_certificate_status(certificate_status, children.frontend->id()));
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    if (stopping)
        return 0;
    host.stage("https");
    deadline = Clock::now() + std::chrono::seconds(15);
    ready = false;
    while (!stopping && Clock::now() < deadline) {
        pump_owner();
        if (stopping)
            break;
        children.check();
        if (https_ready(settings)) {
            ready = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    if (stopping)
        return 0;
    if (!ready)
        throw std::runtime_error("Local HTTPS endpoint did not become ready");
    https_verified = true;
    if(settings.observer) {
        children.readiness_network=std::make_unique<ReadinessNetwork>();
        children.network_observation_healthy=children.readiness_network->poll().healthy;
        children.readiness=std::make_unique<ReadinessManager>(*settings.observer,
            binary_directory/"traverse-readiness-agent",(sockets.directory/"s").string(),children.service->id());
        children.readiness->start();
    }
    std::optional<TlsCertificateStatus> checked_certificate;
    if(children.readiness)checked_certificate=read_tls_certificate_status(certificate_status,children.frontend->id());
    host.stage("sharing", "ready");
    std::cout << "Traverse URL: " << settings.public_url()
              << "\nLocal HTTPS verified. External reachability is not yet verified. "
                 "Use the local pairing dialog to connect; press Ctrl+C to stop.\n"
              << std::flush;
    while (!stopping) {
        pump_owner();
        if (stopping)
            break;
        children.check();
        if (!owner_armed())
            break;
        auto certificate =
            certificate_observer.observe(certificate_status, children.frontend->id());
        if(children.readiness) {
            auto network=children.readiness_network->poll();
            if(network.changed || network.healthy!=children.network_observation_healthy)children.readiness->invalidate();
            children.network_observation_healthy=network.healthy;
            if(bool(certificate)!=bool(checked_certificate) ||
               (certificate && checked_certificate &&
                (certificate->revision!=checked_certificate->revision || certificate->available!=checked_certificate->available ||
                 certificate->fingerprint!=checked_certificate->fingerprint)))children.readiness->invalidate();
            checked_certificate=certificate;
            children.readiness->tick();
        }
        if (children.certificates) {
            children.certificates->tick();
            if (certificate)
                children.certificates->frontend(*certificate);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return 0;
}
} // namespace traverse
