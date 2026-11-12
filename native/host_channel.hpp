#pragma once
#include <cstdint>
#include <deque>
#include <functional>
#include <nlohmann/json.hpp>
#include <string>
#include <sys/types.h>
#include <vector>

namespace traverse {
enum class HostAction { Status, NewCode, CheckConnection, ExportCA, Stop };
struct HostCommand {
    std::uint64_t request_id;
    HostAction action;
};

// Only the explicitly inherited socket from the same-UID parent is accepted.
// Nonblocking transport keeps owner EOF and Stop readable during backpressure.
class HostChannel {
    int descriptor = -1;
    bool requested = false, ended = false, invalid = false;
    const char *reason = "";
    std::vector<unsigned char> incoming;
    std::deque<std::string> outgoing;
    size_t sent = 0;
    void fail(const char *code) noexcept;
    void flush();

  public:
    HostChannel() = default;
    HostChannel(int fd, pid_t parent);
    ~HostChannel();
    HostChannel(const HostChannel &) = delete;
    HostChannel &operator=(const HostChannel &) = delete;
    bool enabled() const {
        return requested;
    }
    bool closed() const {
        return ended;
    }
    bool failed() const {
        return invalid;
    }
    bool pending_output() const {
        return !outgoing.empty();
    }
    const char *failure() const {
        return reason;
    }
    std::vector<HostCommand> receive();
    void send(const nlohmann::json &message);
    void close() noexcept;
};

class HostSupervisor {
    HostChannel channel;
    std::string instance;
    const char *stage_name = "configuration", *phase_name = "starting";
    bool stopping = false;
    std::function<nlohmann::json()> provider, refresh, check_connection, export_ca;
    nlohmann::json snapshot() const;

  public:
    HostSupervisor() = default;
    HostSupervisor(int fd, pid_t parent, std::string identity);
    bool enabled() const {
        return channel.enabled();
    }
    bool failed() const {
        return channel.failed();
    }
    const char *stage() const {
        return stage_name;
    }
    void bind(std::function<nlohmann::json()> state, std::function<nlohmann::json()> new_code = {},
              std::function<nlohmann::json()> connection_check = {},
              std::function<nlohmann::json()> public_ca = {});
    void unbind();
    void stage(const char *name, const char *phase = "starting");
    void failure();
    bool pump();
};
} // namespace traverse
