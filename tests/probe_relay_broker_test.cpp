#include "probe_relay_broker.hpp"
#include "probe_relay_routes.hpp"
#include "readiness_relay.hpp"
#include <arpa/inet.h>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <future>
#include <iostream>
#include <nlohmann/json.hpp>
#include <poll.h>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
using namespace traverse;
using Json = nlohmann::json;
static void check(bool ok) { if (!ok) throw std::runtime_error("Broker contract failed"); }
static int connect_socket(const std::string &path) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0); check(fd >= 0);
    sockaddr_un address{}; address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path, path.c_str(), path.size() + 1);
    check(!connect(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address))); return fd;
}
static void send_text(int fd, const std::string &text) {
    auto size = htonl(static_cast<std::uint32_t>(text.size()));
    check(send(fd, &size, sizeof(size), MSG_NOSIGNAL) == sizeof(size));
    check(send(fd, text.data(), text.size(), MSG_NOSIGNAL) == static_cast<ssize_t>(text.size()));
}
static Json receive(int fd) {
    pollfd event{fd,POLLIN,0}; check(poll(&event,1,3000) > 0);
    std::uint32_t size = 0; check(recv(fd,&size,sizeof(size),MSG_WAITALL) == sizeof(size));
    size = ntohl(size); check(size && size < 1024);
    std::string text(size,'\0'); check(recv(fd,text.data(),size,MSG_WAITALL) == size);
    return Json::parse(text);
}
static Json begin(const std::string &id) { return {{"schemaVersion",1},{"type","begin"},{"lease",id},{"port",12345}}; }
static void rejected(const std::string &path, const std::string &text) {
    int fd = connect_socket(path); send_text(fd,text); check(receive(fd).at("status") == "invalid"); close(fd);
}
int main() {
    char pattern[] = "/tmp/traverse-broker-XXXXXX";
    auto *directory = mkdtemp(pattern); if (!directory) return 1;
    std::string path = std::string(directory) + "/p";
    try {
        auto routes = std::make_shared<ProbeRelayRoutes>();
        std::atomic<bool> cancel{false};
        ProbeRelayBroker broker(path,getpid(),routes);
        struct stat identity{}; check(!lstat(path.c_str(),&identity) && (identity.st_mode & 0777) == 0600);
        const std::string first(64,'a'), second(64,'b'), third(64,'c'), fourth(64,'d');
        {
            ProbeRelayLease lease(path,first,12345,cancel);
            auto route = routes->find(probe_relay_alpn(first)); check(route && route->port == 12345);
            rejected(path,begin(first).dump());
            check(routes->find(probe_relay_alpn(first)) == route); // Duplicate begin cannot revoke its owner.
            std::promise<void> cancelled; auto signalled = cancelled.get_future();
            auto token = route->attach([&] { cancelled.set_value(); });
            auto ending = std::async(std::launch::async,[&] { return lease.end(cancel); });
            check(signalled.wait_for(std::chrono::seconds(3)) == std::future_status::ready);
            check(ending.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready);
            token.reset(); check(ending.get());
            check(!routes->find(probe_relay_alpn(first)));
        }
        check(ProbeRelayLease::cancel_reserved(path,second,cancel));
        rejected(path,begin(second).dump()); // End before begin leaves a tombstone.
        {
            ProbeRelayLease lease(path,third,12345,cancel);
            check(routes->find(probe_relay_alpn(third)) != nullptr);
        }
        // A subsequent acknowledged end observes and drains the EOF revocation.
        check(ProbeRelayLease::cancel_reserved(path,third,cancel));
        check(!routes->find(probe_relay_alpn(third)));
        auto malformed = begin(fourth); malformed["capture"] = true;
        rejected(path,malformed.dump());
        rejected(path,"{\"schemaVersion\":1,\"type\":\"end\",\"type\":\"end\",\"lease\":\"" + fourth + "\"}");
        malformed = begin(fourth); malformed["port"] = 65536; rejected(path,malformed.dump());
        malformed = begin(fourth); malformed["lease"] = std::string(64,'z'); rejected(path,malformed.dump());
        rejected(path," " + begin(fourth).dump());
        pid_t child = fork(); check(child >= 0);
        if (!child) {
            int fd = connect_socket(path);
            pollfd event{fd,POLLIN,0};
            char byte = 0;
            bool denied = poll(&event,1,3000) > 0 && recv(fd,&byte,1,0) <= 0;
            close(fd); _exit(denied ? 0 : 2);
        }
        int status = 0; check(waitpid(child,&status,0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
        ProbeRelayLease held(path,fourth,12345,cancel);
        auto active = routes->find(probe_relay_alpn(fourth)); check(active != nullptr);
        std::shared_ptr<void> token;
        token = active->attach([&] { token.reset(); });
        auto first_stop = std::async(std::launch::async,[&] { broker.stop(); });
        auto second_stop = std::async(std::launch::async,[&] { broker.stop(); });
        first_stop.get(); second_stop.get();
        check(active->stopped && !routes->find(probe_relay_alpn(fourth)));
        check(lstat(path.c_str(),&identity) < 0 && errno == ENOENT);
        cancel = true;
        check(!ProbeRelayLease::cancel_reserved(path,std::string(64,'e'),cancel));
        check(!chmod(directory,0755));
        bool denied = false;
        try { ProbeRelayBroker invalid(path,getpid(),routes); } catch (...) { denied = true; }
        check(denied); check(!chmod(directory,0700));
        // An occupied path belongs to its creator and must survive rejection.
        int marker = socket(AF_UNIX,SOCK_STREAM | SOCK_CLOEXEC,0); check(marker >= 0);
        sockaddr_un address{}; address.sun_family = AF_UNIX;
        std::memcpy(address.sun_path,path.c_str(),path.size()+1);
        check(!bind(marker,reinterpret_cast<sockaddr *>(&address),sizeof(address)));
        denied = false;
        try { ProbeRelayBroker invalid(path,getpid(),routes); } catch (...) { denied = true; }
        check(denied && !lstat(path.c_str(),&identity));
        close(marker); check(!unlink(path.c_str()));
        check(!rmdir(directory));
        std::cout << "Private relay owner, lifecycle, drain and protocol checks passed\n";
        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
