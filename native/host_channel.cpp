#include "host_channel.hpp"
#include <cerrno>
#include <chrono>
#include <csignal>
#include <fcntl.h>
#include <limits>
#include <set>
#include <stdexcept>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

namespace traverse {
HostChannel::HostChannel(int fd, pid_t parent) : descriptor(fd), requested(true) {
    try {
        struct stat metadata{};
        sockaddr_un address{};
        socklen_t address_size = sizeof(address);
        ucred peer{};
        socklen_t peer_size = sizeof(peer);
        int type = 0;
        socklen_t type_size = sizeof(type);
        if (fd < 3 || parent <= 1 || getppid() != parent || fstat(fd, &metadata) ||
            !S_ISSOCK(metadata.st_mode) || metadata.st_uid != geteuid() ||
            getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &type_size) || type != SOCK_STREAM ||
            getpeername(fd, reinterpret_cast<sockaddr *>(&address), &address_size) ||
            address.sun_family != AF_UNIX ||
            getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &peer_size) ||
            peer_size != sizeof(peer) || peer.uid != geteuid() || peer.pid != parent)
            throw std::runtime_error("Owner channel must be a connected socket from your parent");
        int flags = fcntl(fd, F_GETFD), status = fcntl(fd, F_GETFL);
        if (flags < 0 || status < 0 || fcntl(fd, F_SETFD, flags | FD_CLOEXEC) ||
            fcntl(fd, F_SETFL, status | O_NONBLOCK) || prctl(PR_SET_PDEATHSIG, SIGTERM) ||
            getppid() != parent)
            throw std::runtime_error("Cannot guard the inherited owner channel");
    } catch (...) {
        close();
        throw;
    }
}

HostChannel::~HostChannel() {
    close();
}

void HostChannel::close() noexcept {
    if (descriptor >= 0) {
        ::close(descriptor);
        descriptor = -1;
    }
    ended = requested;
}

void HostChannel::fail(const char *code) noexcept {
    invalid = true;
    reason = code;
    close();
}

void HostChannel::flush() {
    while (!ended && !outgoing.empty()) {
        const auto &frame = outgoing.front();
        auto count = ::send(descriptor, frame.data() + sent, frame.size() - sent, MSG_NOSIGNAL);
        if (count > 0) {
            sent += static_cast<size_t>(count);
            if (sent == frame.size()) {
                outgoing.pop_front();
                sent = 0;
            }
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return;
        } else {
            fail("owner-write-failed");
        }
    }
}

void HostChannel::send(const nlohmann::json &message) {
    if (!requested || ended)
        return;
    auto body = message.dump();
    if (body.size() > std::numeric_limits<std::uint32_t>::max())
        throw std::runtime_error("Owner message cannot be represented by the framing protocol");
    auto length = static_cast<std::uint32_t>(body.size());
    std::string frame;
    for (int shift : {24, 16, 8, 0})
        frame.push_back(static_cast<char>((length >> shift) & 0xff));
    frame += body;
    outgoing.push_back(std::move(frame));
    flush();
}

std::vector<HostCommand> HostChannel::receive() {
    std::vector<HostCommand> commands;
    if (!requested || ended)
        return commands;
    flush();
    if (ended)
        return commands;
    unsigned char bytes[16384];
    ssize_t count;
    do {
        count = recv(descriptor, bytes, sizeof(bytes), 0);
    } while (count < 0 && errno == EINTR);
    if (count > 0) {
        incoming.insert(incoming.end(), bytes, bytes + count);
    } else if (!count) {
        close();
        return commands;
    } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
        fail("owner-read-failed");
        return commands;
    }
    while (incoming.size() >= 4) {
        std::uint32_t length = 0;
        for (unsigned index = 0; index < 4; ++index)
            length = (length << 8) | incoming[index];
        if (!length) {
            fail("owner-invalid-frame");
            return {};
        }
        auto frame_size = static_cast<size_t>(length) + 4;
        if (incoming.size() < frame_size)
            break;
        bool duplicate = false;
        std::set<std::string> keys;
        auto value = nlohmann::json::parse(
            incoming.begin() + 4, incoming.begin() + frame_size,
            [&](int depth, nlohmann::json::parse_event_t event, nlohmann::json &part) {
                if (depth == 1 && event == nlohmann::json::parse_event_t::key &&
                    !keys.insert(part.get<std::string>()).second)
                    duplicate = true;
                return true;
            },
            false);
        if (duplicate || !value.is_object() || value.size() != 3 ||
            !value.contains("schemaVersion") || !value["schemaVersion"].is_number_integer() ||
            value["schemaVersion"] != 1 || !value.contains("requestId") ||
            !value["requestId"].is_number_unsigned() || !value.contains("action") ||
            !value["action"].is_string()) {
            fail("owner-invalid-command");
            return {};
        }
        auto action = value["action"].get<std::string>();
        HostAction kind;
        if (action == "status")
            kind = HostAction::Status;
        else if (action == "new-code")
            kind = HostAction::NewCode;
        else if (action == "check-connection")
            kind = HostAction::CheckConnection;
        else if (action == "export-ca")
            kind = HostAction::ExportCA;
        else if (action == "stop")
            kind = HostAction::Stop;
        else {
            fail("owner-unknown-action");
            return {};
        }
        commands.push_back({value["requestId"].get<std::uint64_t>(), kind});
        incoming.erase(incoming.begin(), incoming.begin() + frame_size);
    }
    return commands;
}

HostSupervisor::HostSupervisor(int fd, pid_t parent, std::string identity)
    : channel(fd, parent), instance(std::move(identity)) {
    stage("configuration");
}

nlohmann::json HostSupervisor::snapshot() const {
    auto value = provider ? provider() : nlohmann::json::object();
    value.update({{"instance", instance},
                  {"supervisorPid", getpid()},
                  {"observedMonotonicMs", std::chrono::duration_cast<std::chrono::milliseconds>(
                                              std::chrono::steady_clock::now().time_since_epoch())
                                              .count()},
                  {"stage", stage_name},
                  {"phase", phase_name}});
    return value;
}

void HostSupervisor::bind(std::function<nlohmann::json()> state,
                          std::function<nlohmann::json()> new_code,
                          std::function<nlohmann::json()> connection_check,
                          std::function<nlohmann::json()> public_ca) {
    provider = std::move(state);
    refresh = std::move(new_code);
    check_connection = std::move(connection_check);
    export_ca = std::move(public_ca);
}

void HostSupervisor::unbind() {
    provider = {};
    refresh = {};
    check_connection = {};
    export_ca = {};
}

void HostSupervisor::stage(const char *name, const char *phase) {
    stage_name = name;
    phase_name = phase;
    if (enabled())
        channel.send({{"schemaVersion", 1}, {"event", "state"}, {"state", snapshot()}});
}

void HostSupervisor::failure() {
    unbind();
    stage(stage_name, "failed");
}

bool HostSupervisor::pump() {
    if (!enabled())
        return false;
    auto commands = channel.receive();
    if (channel.closed())
        return true;
    // Stop is never delayed by state production or a blocked reply stream.
    for (const auto &command : commands) {
        if (command.action == HostAction::Stop) {
            stopping = true;
            phase_name = "stopping";
            channel.send({{"schemaVersion", 1},
                          {"requestId", command.request_id},
                          {"ok", true},
                          {"phase", "stopping"}});
            return true;
        }
    }
    for (const auto &command : commands) {
        nlohmann::json response = {{"schemaVersion", 1}, {"requestId", command.request_id}};
        try {
            if (command.action == HostAction::NewCode) {
                if (!refresh) {
                    response.update({{"ok", false}, {"error", "not-ready"}});
                } else {
                    response.update(refresh());
                }
            } else if(command.action == HostAction::CheckConnection) {
                response.update(check_connection ? check_connection() : nlohmann::json{{"ok",false},{"error","not-ready"}});
            } else if(command.action == HostAction::ExportCA) {
                response.update(export_ca ? export_ca() : nlohmann::json{{"ok",false},{"error","not-ready"}});
            } else {
                response["ok"] = true;
            }
            response["state"] = snapshot();
        } catch (const std::exception &) {
            response = {{"schemaVersion", 1},
                        {"requestId", command.request_id},
                        {"ok", false},
                        {"error", "producer-unavailable"}};
        }
        channel.send(response);
    }
    return stopping || channel.closed();
}
} // namespace traverse
