#include "probe_relay_broker.hpp"
#include "probe_relay_routes.hpp"
#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fcntl.h>
#include <mutex>
#include <nlohmann/json.hpp>
#include <poll.h>
#include <set>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace traverse {
namespace {
using Json = nlohmann::json;
struct Descriptor {
    int fd = -1;
    explicit Descriptor(int value = -1) : fd(value) {}
    ~Descriptor() { if (fd >= 0) close(fd); }
    Descriptor(const Descriptor &) = delete;
    Descriptor &operator=(const Descriptor &) = delete;
};
void require(bool ok) { if (!ok) throw std::runtime_error("Private relay channel unavailable"); }
void validate_identity(const std::string &id) {
    require(id.size() == 64 && id.find_first_not_of("0123456789abcdef") == std::string::npos);
}
sockaddr_un socket_address(const std::string &path) {
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    require(std::filesystem::path(path).is_absolute() && path.size() < sizeof(address.sun_path) &&
            path.find('\0') == std::string::npos);
    std::memcpy(address.sun_path, path.c_str(), path.size() + 1);
    return address;
}
bool transfer(int fd, void *buffer, size_t length, bool output, const std::atomic<bool> &cancel) {
    auto *bytes = static_cast<unsigned char *>(buffer);
    while (length && !cancel) {
        pollfd event{fd, static_cast<short>(output ? POLLOUT : POLLIN), 0};
        int ready = poll(&event, 1, 100);
        if (ready < 0) { if (errno == EINTR) continue; return false; }
        if (!ready) continue;
        auto count = output ? send(fd, bytes, length, MSG_NOSIGNAL) : recv(fd, bytes, length, 0);
        if (count > 0) { bytes += count; length -= static_cast<size_t>(count); }
        else if (!count || (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)) return false;
    }
    return length == 0;
}
bool send_frame(int fd, const Json &value, const std::atomic<bool> &cancel) {
    auto text = value.dump();
    auto length = htonl(static_cast<std::uint32_t>(text.size()));
    return transfer(fd, &length, sizeof(length), true, cancel) &&
           transfer(fd, text.data(), text.size(), true, cancel);
}
Json receive_frame(int fd, const std::atomic<bool> &cancel) {
    std::uint32_t size_be = 0;
    require(transfer(fd, &size_be, sizeof(size_be), false, cancel));
    auto length = ntohl(size_be);
    // Largest compact request: fixed schema, one 64-hex lease and uint16 port.
    constexpr size_t maximum = sizeof("{\"schemaVersion\":1,\"type\":\"begin\",\"lease\":\"\",\"port\":65535}") - 1 + 64;
    require(length && length <= maximum);
    std::string text(length, '\0');
    require(transfer(fd, text.data(), text.size(), false, cancel));
    require(text.find_first_of(" \t\r\n") == std::string::npos);
    bool duplicate = false;
    std::set<std::string> keys;
    auto value = Json::parse(text, [&](int depth, Json::parse_event_t event, Json &item) {
        if (depth == 1 && event == Json::parse_event_t::key && !keys.insert(item.get<std::string>()).second)
            duplicate = true;
        return true;
    });
    require(!duplicate && value.is_object() && value.dump().size() == text.size() &&
            value.at("schemaVersion").is_number_unsigned() && value.at("schemaVersion") == 1);
    return value;
}
Json request(const char *type, const std::string &id) {
    validate_identity(id);
    return {{"schemaVersion",1},{"type",type},{"lease",id}};
}
int connect_owner(const std::string &path, const std::atomic<bool> &cancel) {
    auto address = socket_address(path);
    Descriptor peer(socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));
    require(peer.fd >= 0 && !cancel);
    int result = connect(peer.fd, reinterpret_cast<sockaddr *>(&address), sizeof(address));
    if (result && errno != EINPROGRESS && errno != EAGAIN) require(false);
    while (result && !cancel) {
        pollfd event{peer.fd, POLLOUT, 0};
        result = poll(&event, 1, 100);
        if (result < 0 && errno == EINTR) continue;
        require(result >= 0);
        if (!result) { result = -1; continue; }
        int error = 0; socklen_t size = sizeof(error);
        require(!getsockopt(peer.fd, SOL_SOCKET, SO_ERROR, &error, &size) && !error);
        result = 0;
    }
    require(!cancel);
    ucred credentials{}; socklen_t size = sizeof(credentials);
    require(!getsockopt(peer.fd, SOL_SOCKET, SO_PEERCRED, &credentials, &size) &&
            size == sizeof(credentials) && credentials.uid == geteuid());
    int fd = peer.fd; peer.fd = -1;
    return fd;
}
bool acknowledged(int fd, const char *status, const std::atomic<bool> &cancel) {
    auto reply = receive_frame(fd, cancel);
    return reply.size() == 2 && reply.at("status") == status;
}
}
struct ProbeRelayBroker::Impl {
    std::string path;
    pid_t owner;
    std::shared_ptr<ProbeRelayRoutes> routes;
    Descriptor listener;
    struct stat identity{};
    bool owns_socket = false;
    std::atomic<bool> stopped{false};
    std::mutex stop_mutex;
    struct Peer { Descriptor socket; std::atomic<bool> done{false}; explicit Peer(int fd) : socket(fd) {} };
    struct Worker { std::shared_ptr<Peer> peer; std::thread thread; };
    std::vector<Worker> workers;
    std::thread acceptor;
    Impl(const std::string &name, pid_t pid, std::shared_ptr<ProbeRelayRoutes> registry)
        : path(name), owner(pid), routes(std::move(registry)) {
        require(owner > 1 && routes);
        auto address = socket_address(path);
        auto parent = std::filesystem::path(path).parent_path();
        Descriptor directory(open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
        struct stat before{}, after{};
        require(directory.fd >= 0 && !fstat(directory.fd, &before) &&
                before.st_uid == geteuid() && (before.st_mode & 0777) == 0700);
        listener.fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        require(listener.fd >= 0 && !bind(listener.fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)));
        try {
            require(!lstat(path.c_str(), &identity) && S_ISSOCK(identity.st_mode) && identity.st_uid == geteuid());
            owns_socket = true;
            require(!lstat(parent.c_str(), &after) && before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
                    !chmod(path.c_str(), 0600) && !listen(listener.fd, SOMAXCONN));
            acceptor = std::thread([this] { accept_loop(); });
        } catch (...) { remove_socket(); throw; }
    }
    ~Impl() { stop(); }
    void remove_socket() {
        struct stat current{};
        if (owns_socket && !lstat(path.c_str(), &current) && current.st_dev == identity.st_dev &&
            current.st_ino == identity.st_ino && current.st_uid == geteuid()) unlink(path.c_str());
        owns_socket = false;
    }
    bool reply(int fd, const char *status) {
        return send_frame(fd, {{"schemaVersion",1},{"status",status}}, stopped);
    }
    void serve(int fd) {
        std::string active;
        try {
            ucred credentials{}; socklen_t size = sizeof(credentials);
            if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &size) || size != sizeof(credentials) ||
                credentials.uid != geteuid() || credentials.pid != owner) return;
            auto value = receive_frame(fd, stopped);
            auto id = value.at("lease").get<std::string>(); validate_identity(id);
            auto type = value.at("type").get<std::string>();
            if (type == "end" && value.size() == 3) {
                routes->revoke(id); reply(fd, "ended"); return;
            }
            require(type == "begin" && value.size() == 4 && value.at("port").is_number_unsigned());
            auto port = value.at("port").get<std::uint64_t>(); require(port && port <= 65535);
            routes->install(id, static_cast<std::uint16_t>(port));
            active = id;
            if (reply(fd, "installed")) {
                auto end = receive_frame(fd, stopped);
                require(end == request("end", id));
                routes->revoke(id); active.clear(); reply(fd, "ended");
            }
        } catch (...) {
            // Revoke before any failure acknowledgement, including owner EOF.
            if (!active.empty()) { routes->revoke(active); active.clear(); }
            reply(fd, "invalid");
        }
        if (!active.empty()) routes->revoke(active);
    }
    void accept_loop() {
        while (!stopped) {
            for (auto it = workers.begin(); it != workers.end();) {
                if (it->peer->done) { it->thread.join(); it = workers.erase(it); }
                else ++it;
            }
            pollfd event{listener.fd, POLLIN, 0};
            if (poll(&event, 1, 100) <= 0 || !(event.revents & POLLIN)) continue;
            Descriptor pending(accept4(listener.fd, nullptr, nullptr, SOCK_CLOEXEC | SOCK_NONBLOCK));
            if (pending.fd < 0) continue;
            std::shared_ptr<Peer> peer;
            try {
                peer = std::make_shared<Peer>(pending.fd); pending.fd = -1;
                workers.push_back({peer,{}});
                workers.back().thread = std::thread([this,peer] {
                    serve(peer->socket.fd); shutdown(peer->socket.fd, SHUT_RDWR); peer->done = true;
                });
            } catch (...) {
                if (!workers.empty() && workers.back().peer == peer && !workers.back().thread.joinable()) workers.pop_back();
            }
        }
    }
    void stop() {
        std::lock_guard lock(stop_mutex);
        if (stopped.exchange(true)) return;
        shutdown(listener.fd, SHUT_RDWR);
        if (acceptor.joinable()) acceptor.join();
        for (auto &worker : workers) shutdown(worker.peer->socket.fd, SHUT_RDWR);
        for (auto &worker : workers) if (worker.thread.joinable()) worker.thread.join();
        workers.clear();
        if (listener.fd >= 0) { close(listener.fd); listener.fd = -1; }
        remove_socket();
    }
};
ProbeRelayBroker::ProbeRelayBroker(const std::string &path, pid_t owner, std::shared_ptr<ProbeRelayRoutes> routes)
    : impl(std::make_unique<Impl>(path, owner, std::move(routes))) {}
ProbeRelayBroker::~ProbeRelayBroker() = default;
void ProbeRelayBroker::stop() { impl->stop(); }
ProbeRelayLease::ProbeRelayLease(const std::string &path, const std::string &lease,
                               std::uint16_t backend, const std::atomic<bool> &cancel) : identity(lease) {
    auto begin = request("begin", identity); require(backend != 0); begin["port"] = backend;
    Descriptor pending(connect_owner(path, cancel));
    require(send_frame(pending.fd, begin, cancel) && acknowledged(pending.fd, "installed", cancel));
    fd = pending.fd; pending.fd = -1;
}
ProbeRelayLease::~ProbeRelayLease() { if (fd >= 0) close(fd); }
bool ProbeRelayLease::end(const std::atomic<bool> &cancel) {
    if (fd < 0) return false;
    Descriptor pending(fd); fd = -1;
    try { return send_frame(pending.fd, request("end", identity), cancel) && acknowledged(pending.fd, "ended", cancel); }
    catch (...) { return false; }
}
bool ProbeRelayLease::cancel_reserved(const std::string &path, const std::string &lease, const std::atomic<bool> &cancel) {
    try {
        auto end = request("end", lease);
        Descriptor peer(connect_owner(path, cancel));
        return send_frame(peer.fd, end, cancel) && acknowledged(peer.fd, "ended", cancel);
    } catch (...) { return false; }
}
}
