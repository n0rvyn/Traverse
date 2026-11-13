#include "probe_relay_routes.hpp"
#include "readiness_relay.hpp"
#include <condition_variable>
#include <stdexcept>
#include <vector>

namespace traverse {
struct ProbeRelayRoute::State {
    std::mutex mutex;
    std::condition_variable drained;
    bool revoked = false;
    std::map<const void *,std::function<void()>> connections;
};
ProbeRelayRoute::ProbeRelayRoute(std::string identity, std::uint16_t backend)
    : state(std::make_shared<State>()),alpn(std::move(identity)),port(backend) {}
ProbeRelayRoute::~ProbeRelayRoute() { revoke(); }
std::shared_ptr<void> ProbeRelayRoute::attach(std::function<void()> cancel) {
    if (!cancel) throw std::runtime_error("Probe relay cancellation is required");
    struct Attachment {
        std::shared_ptr<State> owner;
        bool registered=false;
        ~Attachment() {
            if (!registered) return;
            std::lock_guard lock(owner->mutex);
            owner->connections.erase(this);
            owner->drained.notify_all();
        }
    };
    auto token=std::make_shared<Attachment>();token->owner=state;
    std::lock_guard lock(state->mutex);
    if (state->revoked) throw std::runtime_error("Probe relay route ended");
    if (!state->connections.emplace(token.get(),std::move(cancel)).second)
        throw std::runtime_error("Probe relay connection identity collision");
    token->registered=true;
    return token;
}
void ProbeRelayRoute::revoke() {
    std::vector<std::function<void()>> cancel;
    {
        std::lock_guard lock(state->mutex);
        if (!state->revoked) {
            for (const auto &connection:state->connections) cancel.push_back(connection.second);
            state->revoked=true;stopped=true;
        }
    }
    for (const auto &close:cancel) close();
    std::unique_lock lock(state->mutex);
    state->drained.wait(lock,[&]{return state->connections.empty();});
}
ProbeRelayRoutes::~ProbeRelayRoutes() { stop(); }
void ProbeRelayRoutes::install(const std::string &lease,std::uint16_t port) {
    const auto alpn=probe_relay_alpn(lease);
    if (!port) throw std::runtime_error("Private probe relay backend required");
    auto route=std::shared_ptr<ProbeRelayRoute>(new ProbeRelayRoute(alpn,port));
    std::lock_guard lock(mutex);
    if (stopped || ended.count(alpn) || !routes.emplace(alpn,std::move(route)).second)
        throw std::runtime_error("Probe relay route unavailable");
}
std::shared_ptr<ProbeRelayRoute> ProbeRelayRoutes::find(const std::string &alpn) const {
    std::lock_guard lock(mutex);
    auto it=routes.find(alpn);
    return !stopped && !ended.count(alpn) && it!=routes.end() && !it->second->stopped ? it->second : nullptr;
}
void ProbeRelayRoutes::revoke(const std::string &lease) {
    const auto alpn=probe_relay_alpn(lease);
    std::shared_ptr<ProbeRelayRoute> route;
    {
        std::lock_guard lock(mutex);
        ended.insert(alpn);
        auto it=routes.find(alpn);
        if(it==routes.end()) return;
        route=it->second;
    }
    route->revoke();
    std::lock_guard lock(mutex);
    auto it=routes.find(alpn);
    if(it!=routes.end() && it->second==route) routes.erase(it);
}
void ProbeRelayRoutes::stop() {
    std::map<std::string,std::shared_ptr<ProbeRelayRoute>> ending;
    {
        std::lock_guard lock(mutex);
        ending=routes;stopped=true;
    }
    for (const auto &route:ending) route.second->revoke();
    std::lock_guard lock(mutex);
    routes.clear();
}
}
