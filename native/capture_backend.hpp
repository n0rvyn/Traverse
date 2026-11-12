#pragma once
#include "portal_session.hpp"
#include <memory>
#include <string>
#include <vector>

namespace traverse {
// Internal transport only. Callers supply the granted stream and explicit
// output format/rate; this component chooses no user-facing quality defaults.
class PipeWireCapture {
  public:
    enum class State { Starting, Streaming, Stopped, Revoked, Failed };
    struct Options { std::string runtime_directory, output_caps; };
    struct Snapshot {
        State state = State::Starting;
        std::string error, socket_path, caps, format, provider_dbus_version;
        unsigned width = 0, height = 0;
        std::vector<int> strides;
        std::uint64_t frames = 0, fd_frames = 0, dmabuf_frames = 0;
        std::optional<std::uint64_t> first_pts, last_pts, drm_modifier;
        std::optional<std::uint32_t> drm_fourcc;
    };
    static std::string target(const PortalSession::Stream &);
    static void validate(const Options &);
    PipeWireCapture(PortalSession::Connection, const PortalSession::Stream &, Options);
    ~PipeWireCapture();
    PipeWireCapture(const PipeWireCapture &) = delete;
    PipeWireCapture &operator=(const PipeWireCapture &) = delete;
    Snapshot snapshot() const;
    // Borrowed until destruction. Signals control-state/geometry changes,
    // including first Streaming and terminal state, not per-frame counters.
    int state_descriptor() const noexcept;
    // A barrier: pipeline/core teardown completes before the reserved protocol
    // descriptor is released. No session ownership or input path is changed.
    void stop();
  private:
    struct Impl;
    std::unique_ptr<Impl> impl;
};
}
