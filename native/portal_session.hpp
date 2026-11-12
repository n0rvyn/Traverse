#pragma once
#include <cstdint>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <stdexcept>
#include <utility>
#include <vector>

namespace traverse {
// Private Wayland authority; capability readiness is never a permission grant.
class PortalSession {
    struct Impl;
  public:
    enum class State { Probing, CapabilitiesReady, Requesting, WaitingPermission, Granted, NotGranted, Failed, Stopped, Closed };
    enum class Failure { None, Unavailable, Cancelled, Transport, Method, InvalidResponse, InvalidInput };
    enum class InputMethod { Undetermined, PortalDbus, Eis };
    struct ConnectionError : std::runtime_error {
        Failure failure;
        ConnectionError(Failure kind, const std::string &message) : std::runtime_error(message), failure(kind) {}
    };
    // PortalSession remains the authority owner. Revocation is persistent pipe
    // EOF, so each consumer can poll without consuming a shared wakeup. EIS
    // additionally holds the sole consumer-lifetime writer; losing it requests
    // authority shutdown. Borrowed descriptors stay reserved until destruction.
    class Connection {
      public:
        enum class Protocol { None, PipeWire, Eis };
        Connection() noexcept = default;
        ~Connection();
        Connection(Connection &&) noexcept;
        Connection &operator=(Connection &&) noexcept;
        Connection(const Connection &) = delete;
        Connection &operator=(const Connection &) = delete;
        int descriptor() const noexcept { return fd; }
        int revocation_descriptor() const noexcept { return revoked; }
        Protocol protocol() const noexcept { return kind; }
        bool valid() const noexcept;
      private:
        friend struct Impl;
        Connection(int connection, int notification, Protocol protocol, int lifetime = -1) noexcept
            : fd(connection), revoked(notification), consumer(lifetime), kind(protocol) {}
        int fd = -1, revoked = -1, consumer = -1;
        Protocol kind = Protocol::None;
    };
    struct Request {
        std::uint32_t devices, source_types, cursor_mode;
        bool multiple;
        std::string parent_window;
    };
    struct Stream {
        std::uint32_t node;
        std::optional<std::uint32_t> source_type;
        std::optional<std::uint64_t> serial;
        std::optional<std::pair<std::int32_t, std::int32_t>> position, logical_size;
        std::optional<std::string> mapping_id;
    };
    struct Snapshot {
        State state = State::Probing;
        Failure failure = Failure::None;
        std::uint32_t remote_version = 0, screen_version = 0;
        std::uint32_t devices = 0, sources = 0;
        std::optional<std::uint32_t> cursor_modes;
        std::optional<std::uint32_t> portal_response;
        std::uint32_t granted_devices = 0;
        InputMethod input_method = InputMethod::Undetermined;
        std::vector<Stream> streams;
        std::string operation, error;
    };
    struct Input {
        enum class Kind { PointerAbsolute, PointerButton, PointerAxisDiscrete, KeyboardKeysym, KeyboardKeycode };
        Kind kind;
        std::uint32_t stream = 0;
        double x = 0, y = 0;
        std::int32_t code = 0; // evdev button/keyboard keycode, discrete axis or keysym
        std::int32_t steps = 0;
        bool down = false;
    };
    // Internal transport only: callers retain authentication, DOM-key/layout
    // validation and hold ownership. KeyboardKeycode uses Linux evdev, never
    // X11 keycode+8. It is not a public raw-keycode input endpoint.
    // Completes on the method reply, never on mere queue acceptance.
    std::future<void> notify_input(const Input &);
    PortalSession();
    ~PortalSession();
    PortalSession(const PortalSession &) = delete;
    PortalSession &operator=(const PortalSession &) = delete;
    Snapshot snapshot() const;
    // Borrowed until destruction. Drain wakeup bytes, then inspect snapshot
    // and all pending futures. Signals state changes and settled operations;
    // the pipe remains open after Stop, with terminal state in snapshot().
    int state_descriptor() const noexcept;
    bool request(const Request &);
    // Transfers each connection exactly once. A dup is the same protocol stream,
    // never an independent PipeWire/EIS client. Stop still revokes the session
    // through its private bus even after the consumer takes a descriptor.
    int take_pipewire_fd();
    int take_eis_fd();
    // Sole EIS consumer lifetime: dropping this connection revokes the session,
    // even if other components retain capture descriptors. Never duplicates a
    // consumer writer; move it to the component that actually owns input.
    Connection take_eis_connection();
    // Uses the prepared, unconsumed initial connection once, then obtains a
    // fresh remote per call. Abandoning a future closes its eventual result.
    std::future<Connection> open_pipewire_connection();
    // Cancels queued work; legacy dispatched holds receive terminal releases
    // flushed to the private bus before owner closure. Does not wait for
    // stalled method replies or turn cleanup into an input acknowledgment.
    void stop();

  private:
    std::unique_ptr<Impl> impl;
};
} // namespace traverse
