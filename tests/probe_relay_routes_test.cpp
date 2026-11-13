#include "probe_relay_routes.hpp"
#include "readiness_relay.hpp"
#include <atomic>
#include <future>
#include <iostream>
#include <stdexcept>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#define CHECK(value) do { if (!(value)) throw std::runtime_error("Check failed: " #value); } while (false)
template<class F> void rejects(F action) {bool caught=false;try{action();}catch(const std::exception &){caught=true;}CHECK(caught);}
int main() {
    const std::string a(64,'a'),b(64,'b'),c(64,'c');
    traverse::ProbeRelayRoutes routes;
    routes.install(a,4444);auto old=routes.find(traverse::probe_relay_alpn(a));
    CHECK(old && old->port==4444 && !old->stopped);
    rejects([&]{routes.install(a,5555);});rejects([&]{routes.install(b,0);});
    routes.revoke(b);rejects([&]{routes.install(b,4444);});
    int pair[2];CHECK(socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,pair)==0);
    std::atomic<unsigned> cancelled{0};
    auto use=old->attach([&]{++cancelled;shutdown(pair[0],SHUT_RDWR);});
    std::promise<void> waiting;auto ready=waiting.get_future();
    std::thread worker([&,owned=std::move(use)]() mutable {
        waiting.set_value();char byte;CHECK(recv(pair[0],&byte,1,0)==0);owned.reset();
    });
    ready.get();routes.revoke(a);worker.join();
    CHECK(cancelled==1 && old->stopped && !routes.find(traverse::probe_relay_alpn(a)));
    close(pair[0]);close(pair[1]);
    rejects([&]{old->attach([]{});});rejects([&]{routes.install(a,4444);});
    // The exact backend port is reusable by a fresh identity. An old retained
    // route stays revoked and can never attach to the replacement.
    routes.install(c,4444);auto current=routes.find(traverse::probe_relay_alpn(c));
    CHECK(current && current!=old && current->port==old->port && !current->stopped);
    rejects([&]{old->attach([]{});});
    routes.stop();CHECK(current->stopped);rejects([&]{routes.install(std::string(64,'d'),5555);});
    routes.revoke(a);routes.stop();
    std::cout<<"Probe route revocation, drain and identity reuse checks passed\n";
}
