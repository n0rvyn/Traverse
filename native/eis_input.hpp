#pragma once
#include "portal_session.hpp"

namespace traverse {
// Internal native transport. The caller supplies the authoritative grant and
// selected stream from the same PortalSession. Authentication, DOM/layout
// translation and any cross-process grant validation remain caller boundaries.
class EisInput {
  public:
    enum class State { Starting, Ready, Unavailable, Revoked, Failed, Stopped };
    struct Snapshot {
        State state = State::Starting;
        std::string error;
        std::size_t devices = 0, resumed_devices = 0;
    };
    EisInput(PortalSession::Connection, std::uint32_t granted_devices, PortalSession::Stream);
    ~EisInput();
    EisInput(const EisInput &) = delete;
    EisInput &operator=(const EisInput &) = delete;
    Snapshot snapshot() const;
    // Borrowed until destruction; drain bytes then read snapshot and inspect
    // pending futures. State changes and every settled operation signal it;
    // the pipe stays open after Stop, with terminal state in snapshot().
    int state_descriptor() const noexcept;
    // Completes at an actual in-order EIS protocol barrier, not queue admission.
    std::future<void> submit(PortalSession::Input);
    std::future<void> release_held();
    void stop();
  private:
    struct Impl;
    std::unique_ptr<Impl> impl;
};
} // namespace traverse
