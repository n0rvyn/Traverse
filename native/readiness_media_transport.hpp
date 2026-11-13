#pragma once
#include <cstdint>
#include <memory>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <vector>
namespace traverse {
struct ReadinessMediaPeer { std::string address; std::uint16_t port; };
struct ReadinessMediaRelay { std::uint16_t port; std::string username, credential; };
struct ReadinessMediaConfig {
    std::string peer, nonce;
    bool source = false;
    std::uint16_t port = 0;
    std::vector<std::string> addresses;
    std::vector<ReadinessMediaPeer> peers;
    // Frozen configured public address for a direct check through an explicit
    // same-port NAT mapping. Binding still uses addresses above. Relay-only
    // checks use the actual scoped relay/source addresses instead.
    std::optional<std::string> advertised_address;
    // Only an owned loopback verified-TLS bridge, never a public TURN URI.
    std::optional<ReadinessMediaRelay> relay;
    static ReadinessMediaConfig parse(const nlohmann::json &);
    std::string admit_candidate(const std::string &) const;
    std::string admit_description(const std::string &) const;
};
// Synthetic VP8 and a nonce-only data channel. No capture/input/adapter API.
class ReadinessMediaTransport {
    struct State;
    std::shared_ptr<State> state;
  public:
    explicit ReadinessMediaTransport(const ReadinessMediaConfig &);
    ~ReadinessMediaTransport();
    ReadinessMediaTransport(const ReadinessMediaTransport &) = delete;
    ReadinessMediaTransport &operator=(const ReadinessMediaTransport &) = delete;
    void command(const nlohmann::json &);
    void tick();
    std::vector<nlohmann::json> events();
    bool failed() const;
    void stop();
};
}
