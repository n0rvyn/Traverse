#pragma once
#include <filesystem>
#include <memory>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "readiness_probe_turn.hpp"

namespace traverse {
enum class ReadinessMediaRole { Source, Observer };
struct ReadinessProbeRelayGrant {
    std::vector<std::string> addresses;
    std::uint16_t source_port=0;
    std::string username,credential;
    std::string route;
};
// Private owner of one media UDP endpoint with an immutable source/observer
// role. Source instances also own their dedicated relay. All spawning and
// reaping happens on its persistent thread, never an HTTP handler thread.
// Callers authenticate purpose leases before begin/command, and validate a
// genuine controller before preempt. No public route is registered here.
class ReadinessMedia {
    struct State;
    std::unique_ptr<State> state;
  public:
    explicit ReadinessMedia(std::filesystem::path worker,std::string probe_broker={},
                            ReadinessMediaRole role=ReadinessMediaRole::Source);
    ~ReadinessMedia();
    ReadinessMedia(const ReadinessMedia &) = delete;
    ReadinessMedia &operator=(const ReadinessMedia &) = delete;
    bool begin(const std::string &id, const nlohmann::json &source_config);
    // Prepare the dedicated relay on the same persistent thread. The source
    // can begin later with this same lease after the observer has gathered.
    bool prepare_relay(const std::string &id,const ReadinessProbeRelayGrant &);
    std::optional<std::vector<ReadinessMediaPeer>> relay_allocations(const std::string &id);
    bool command(const std::string &id, const nlohmann::json &command);
    std::vector<nlohmann::json> events();
    // Unknown end reserves a tombstone, so a delayed begin cannot run later.
    // Completion acknowledges actual child reap, not just cancellation intent.
    void end(const std::string &id);
    void preempt();
    void owner_revoked_controller();
    bool idle() const;
    void stop();
};
}
