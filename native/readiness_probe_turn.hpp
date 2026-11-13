#pragma once
#include "readiness_media_transport.hpp"
#include <atomic>
#include <filesystem>
#include <memory>

namespace traverse {
// Called only from the persistent media coordinator. The dedicated process
// has fresh lease credentials, no inherited service authority and no disk state.
class ReadinessProbeTurn {
    struct State;
    std::unique_ptr<State> state;
  public:
    ReadinessProbeTurn(const std::filesystem::path &binary,
                       const std::vector<std::string> &addresses,
                       std::uint16_t source_port, const std::string &username,
                       const std::string &credential);
    ~ReadinessProbeTurn();
    ReadinessProbeTurn(const ReadinessProbeTurn &) = delete;
    ReadinessProbeTurn &operator=(const ReadinessProbeTurn &) = delete;
    bool ready();
    std::uint16_t port() const;
    // Read live socket inodes through this owned, unreaped child. Never infer
    // ownership from an advertised candidate or a system-wide port alone.
    std::vector<ReadinessMediaPeer> allocations();
    // Dedicated synthetic state is disposable. Revoke the frontend route
    // first, then kill/reap without delaying a real controller for TURN expiry.
    void stop();
};
}
