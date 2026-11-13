#pragma once
#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>

namespace traverse {
// An owner-created route has a fixed private backend for its entire lifetime.
// Revocation closes and drains attached streams before returning. Reusing a
// backend port never reactivates an old route object or ALPN identity.
class ProbeRelayRoute {
    struct State;
    std::shared_ptr<State> state;
    friend class ProbeRelayRoutes;
    explicit ProbeRelayRoute(std::string identity, std::uint16_t backend);
  public:
    const std::string alpn;
    const std::uint16_t port;
    std::atomic<bool> stopped{false};
    ~ProbeRelayRoute();
    ProbeRelayRoute(const ProbeRelayRoute &) = delete;
    ProbeRelayRoute &operator=(const ProbeRelayRoute &) = delete;
    // Keep this token for the whole connection. The callback must only cancel
    // owned sockets; it must not wait for that connection or call this registry.
    std::shared_ptr<void> attach(std::function<void()> cancel);
    void revoke();
};
class ProbeRelayRoutes {
    mutable std::mutex mutex;
    bool stopped = false;
    std::map<std::string,std::shared_ptr<ProbeRelayRoute>> routes;
    std::set<std::string> ended;
  public:
    ~ProbeRelayRoutes();
    void install(const std::string &lease_id, std::uint16_t private_backend_port);
    std::shared_ptr<ProbeRelayRoute> find(const std::string &alpn) const;
    void revoke(const std::string &lease_id);
    void stop();
};
}
