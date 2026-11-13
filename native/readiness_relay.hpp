#pragma once
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace traverse {
// This only prevents the pinned native TURN client following a redirect outside
// its verified TLS bridge. Peer authorization lives inside the probe coturn.
class ProbeTurnResponses {
  public:
    using Bytes = std::vector<unsigned char>;
    Bytes receive(const void *bytes, std::size_t size);
    void finish() const;
  private:
    Bytes pending;
    bool failed = false;
};
struct ProbeTlsEndpoint {
    // Numeric, frozen owner-approved pin. No resolver is used by this bridge.
    std::string address, hostname, ca_file, alpn;
    std::uint16_t port = 0;
};
// Internal protocol identity, not an additional public listener or user setting.
std::string probe_relay_alpn(const std::string &lease_id);
// Owns only its outbound socket/TLS state. Caller owns plain_fd and cancellation.
// The connected local TURN socket is never read before identity and ALPN pass.
// Returns false on cancellation; throws on admission/connect/handshake failure.
bool forward_probe_tls(const ProbeTlsEndpoint &, int plain_fd,
                       const std::atomic<bool> &stopped,
                       const std::function<void()> &verified = {});
struct ProbeTlsRelaySnapshot {
    std::uint64_t started = 0, verified = 0, finished = 0, failed = 0;
};
// An owned ephemeral loopback TURN listener for the native ICE worker. Every
// accepted stream uses the same immutable verified remote endpoint and lease.
class ProbeTlsRelay {
    struct Impl;
    std::unique_ptr<Impl> impl;
  public:
    explicit ProbeTlsRelay(const ProbeTlsEndpoint &);
    ~ProbeTlsRelay();
    ProbeTlsRelay(const ProbeTlsRelay &) = delete;
    ProbeTlsRelay &operator=(const ProbeTlsRelay &) = delete;
    std::uint16_t port() const;
    ProbeTlsRelaySnapshot snapshot() const;
    void stop();
};
}
