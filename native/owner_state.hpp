#pragma once
#include "common.hpp"
#include <fcntl.h>
#include <sys/un.h>

namespace traverse {
inline std::pair<int, json> owned_json_request(const std::string &path, pid_t expected,
                                               const char *route, const json *body = nullptr) {
    if (expected <= 1)
        throw std::runtime_error("Private service state peer identity invalid");
    httplib::Client client(path, 80);
    client.set_address_family(AF_UNIX);
    client.set_keep_alive(true);
    client.set_connection_timeout(1, 0);
    client.set_read_timeout(2, 0);
    client.set_write_timeout(2, 0);
    client.set_follow_location(false);
    bool verified = false;
    httplib::Request request;
    request.method = body ? "POST" : "GET";
    request.path = route;
    if (body) {
        request.body = body->dump();
        request.set_header("Content-Type", "application/json");
    }
    // Error replies can close keep-alive before send() returns. Authenticate
    // the live socket at response headers, before accepting any response body.
    request.response_handler = [&](const httplib::Response &) {
        ucred peer{};
        socklen_t size = sizeof(peer);
        verified = !getsockopt(client.socket(), SOL_SOCKET, SO_PEERCRED, &peer, &size) &&
                   size == sizeof(peer) && peer.uid == geteuid() && peer.pid == expected;
        return verified;
    };
    auto response = client.send(request);
    if (!response || !verified)
        throw std::runtime_error("Private service state peer identity invalid");
    return {response->status, json::parse(response->body)};
}

inline json validate_owner_state(json value, pid_t expected) {
    auto now =
        std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch())
            .count();
    auto observed = value.value("observedMonotonicMs", std::int64_t{-1});
    // The response must belong to this request's existing two-second read
    // deadline, not a cached snapshot from an earlier producer or instance.
    if (value.value("schemaVersion", 0) != 1 || value.value("pid", pid_t{-1}) != expected ||
        observed < 0 || observed > now || now - observed > 2000)
        throw std::runtime_error("Private service state is stale or invalid");
    return value;
}

inline json read_owned_state(const std::string &path, pid_t expected, const char *route) {
    auto response = owned_json_request(path, expected, route);
    if (response.first != 200)
        throw std::runtime_error("Private producer state unavailable");
    return validate_owner_state(std::move(response.second), expected);
}

inline json read_owner_state(const std::string &path, pid_t expected) {
    return read_owned_state(path, expected, "/state");
}
// This listener is separate from every HTTP/TLS backend. Its fresh pathname
// belongs to one private instance; cleanup never removes a replacement socket.
class OwnerStateListener {
    std::string path;
    struct stat identity{};
    bool owns = false;
    httplib::Server server;
    std::thread listener;
    std::atomic<bool> listener_failed{false};
    std::mutex startup_mutex;
    std::condition_variable startup_changed;
    bool entered = false, exited = false;

    void remove_owned() noexcept {
        struct stat current{};
        if (owns && !lstat(path.c_str(), &current) && S_ISSOCK(current.st_mode) &&
            current.st_uid == geteuid() && current.st_dev == identity.st_dev &&
            current.st_ino == identity.st_ino)
            unlink(path.c_str());
        owns = false;
    }

  public:
    OwnerStateListener(std::string name, const std::function<void(httplib::Server &)> &routes)
        : path(std::move(name)) {
        auto location = std::filesystem::path(path);
        auto parent = location.parent_path();
        int directory = open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        struct stat before{}, after{}, existing{};
        bool private_parent = directory >= 0 && !fstat(directory, &before) &&
                              before.st_uid == geteuid() && (before.st_mode & 0777) == 0700;
        if (directory >= 0)
            close(directory);
        if (!location.is_absolute() || location.lexically_normal() != location || !private_parent ||
            path.size() >= sizeof(sockaddr_un::sun_path))
            throw std::runtime_error(
                "Owner state requires an absolute socket in a private directory");
        if (!lstat(path.c_str(), &existing) || errno != ENOENT)
            throw std::runtime_error("Owner state socket path already exists or is unavailable");
        try {
            server.set_address_family(AF_UNIX);
            routes(server);
            if (!server.bind_to_port(path, 80))
                throw std::runtime_error("Cannot bind private owner state socket");
            if (lstat(path.c_str(), &identity) || !S_ISSOCK(identity.st_mode) ||
                identity.st_uid != geteuid())
                throw std::runtime_error("Private owner state socket ownership invalid");
            owns = true;
            if (lstat(parent.c_str(), &after) || !S_ISDIR(after.st_mode) ||
                before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
                after.st_uid != geteuid() || (after.st_mode & 0777) != 0700 ||
                chmod(path.c_str(), 0600))
                throw std::runtime_error("Private owner state directory changed");
            server.set_start_handler([this] {
                std::lock_guard lock(startup_mutex);
                entered = true;
                startup_changed.notify_all();
            });
            listener = std::thread([this] {
                if (!server.listen_after_bind())
                    listener_failed = true;
                std::lock_guard lock(startup_mutex);
                exited = true;
                startup_changed.notify_all();
            });
            // stop() cannot close a bound socket until listen_after_bind()
            // has entered. Do not expose a partially started listener.
            std::unique_lock lock(startup_mutex);
            startup_changed.wait(lock, [this] { return entered || exited; });
        } catch (...) {
            server.stop();
            if (listener.joinable())
                listener.join();
            remove_owned();
            throw;
        }
    }
    OwnerStateListener(const OwnerStateListener &) = delete;
    OwnerStateListener &operator=(const OwnerStateListener &) = delete;
    bool failed() const {
        return listener_failed.load();
    }
    ~OwnerStateListener() {
        server.stop();
        if (listener.joinable())
            listener.join();
        remove_owned();
    }
};
} // namespace traverse
