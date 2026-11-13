#pragma once
#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <sys/types.h>

namespace traverse {
class ProbeRelayRoutes;
// Private owner channel. Kernel credentials restrict route management to the
// persistent host service, rather than other children with the same UID.
class ProbeRelayBroker {
    struct Impl;
    std::unique_ptr<Impl> impl;
  public:
    ProbeRelayBroker(const std::string &path, pid_t owner,
                     std::shared_ptr<ProbeRelayRoutes> routes);
    ~ProbeRelayBroker();
    void stop();
};
class ProbeRelayLease {
    int fd = -1;
    std::string identity;
  public:
    ProbeRelayLease(const std::string &path, const std::string &lease,
                    std::uint16_t backend, const std::atomic<bool> &cancel);
    ~ProbeRelayLease();
    ProbeRelayLease(const ProbeRelayLease &) = delete;
    ProbeRelayLease &operator=(const ProbeRelayLease &) = delete;
    // Explicit end waits for attached TLS streams to drain. Destruction closes
    // the channel without blocking; the broker then revokes the lease on EOF.
    bool end(const std::atomic<bool> &cancel);
    static bool cancel_reserved(const std::string &path, const std::string &lease,
                                const std::atomic<bool> &cancel);
};
}
