#include "readiness_relay.hpp"
#include "endpoint_settings.hpp"
#include "tls_stream.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <mutex>
#include <netinet/tcp.h>
#include <openssl/x509v3.h>
#include <poll.h>
#include <stdexcept>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

namespace traverse {
namespace {
[[noreturn]] void invalid() { throw std::runtime_error("Invalid probe TURN response"); }
unsigned u16(const unsigned char *p) { return (unsigned(p[0]) << 8) | p[1]; }
void validate_response(const unsigned char *p, std::size_t size) {
    if (u16(p) >= 0x4000) return; // ChannelData payload is opaque to this bridge.
    if (size < 20 || p[4] != 0x21 || p[5] != 0x12 || p[6] != 0xa4 || p[7] != 0x42)
        invalid();
    const unsigned category = ((u16(p) & 0x10) >> 4) | ((u16(p) & 0x100) >> 7);
    if (category == 0) invalid(); // A TURN server cannot request client actions.
    bool error_seen = false;
    for (std::size_t offset = 20; offset < size;) {
        if (size - offset < 4) invalid();
        auto type = u16(p + offset), length = u16(p + offset + 2);
        const std::size_t padded = (std::size_t(length) + 3) & ~std::size_t{3};
        if (padded > size - offset - 4 || type == 0x8023) invalid();
        if (type == 9) {
            if (error_seen || category != 3 || length < 4) invalid();
            error_seen = true;
            const auto *error = p + offset + 4;
            if (error[0] || error[1] || error[2] < 3 || error[2] > 6 || error[3] > 99)
                invalid();
            if (unsigned(error[2]) * 100 + error[3] == 300) invalid();
        }
        offset += 4 + padded;
    }
    if (category == 3 && !error_seen) invalid();
}
struct Socket {
    int fd = -1;
    ~Socket() { if (fd >= 0) close(fd); }
};
struct ProbeTarget {sockaddr_storage address{};socklen_t size=0;};
ProbeTarget probe_target(const ProbeTlsEndpoint &endpoint) {
    constexpr std::size_t prefix_size = sizeof("traverse-probe/") - 1;
    if (!endpoint.port || endpoint.address.find('\0') != std::string::npos ||
        endpoint.ca_file.find('\0') != std::string::npos || endpoint.alpn.size() < prefix_size ||
        endpoint.alpn != probe_relay_alpn(endpoint.alpn.substr(prefix_size)) ||
        endpoint.hostname != EndpointSettings::normalize_host(endpoint.hostname))
        throw std::runtime_error("Invalid probe TLS endpoint");
    ProbeTarget target;auto &storage=target.address;
    auto *v4 = reinterpret_cast<sockaddr_in *>(&storage);
    auto *v6 = reinterpret_cast<sockaddr_in6 *>(&storage);
    auto &address_size=target.size;
    if (inet_pton(AF_INET, endpoint.address.c_str(), &v4->sin_addr) == 1) {
        v4->sin_family = AF_INET; v4->sin_port = htons(endpoint.port); address_size = sizeof(*v4);
    } else if (inet_pton(AF_INET6, endpoint.address.c_str(), &v6->sin6_addr) == 1) {
        v6->sin6_family = AF_INET6; v6->sin6_port = htons(endpoint.port); address_size = sizeof(*v6);
    } else throw std::runtime_error("Probe TLS destination is not a numeric pin");
    return target;
}
bool wait_socket(int fd, short events, const std::atomic<bool> &stopped) {
    while (!stopped) {
        pollfd event{fd, events, 0};
        int result = poll(&event, 1, 100);
        if (result < 0 && errno == EINTR) continue;
        if (result < 0) throw std::runtime_error("Probe TLS socket wait failed");
        if (result) return true;
    }
    return false;
}
}
ProbeTurnResponses::Bytes ProbeTurnResponses::receive(const void *data, std::size_t size) {
    if (failed) invalid();
    try {
        if (size && !data) invalid();
        const auto *bytes = static_cast<const unsigned char *>(data);
        Bytes output;
        // Incremental framing bounds retained data by the protocol frame length,
        // including when a read coalesces many frames. No application quota.
        std::size_t offset = 0;
        while (offset < size) {
            const std::size_t target = pending.size() < 4 ? 4 :
                u16(pending.data()) < 0x4000 ? 20 + u16(pending.data() + 2) :
                4 + ((std::size_t(u16(pending.data() + 2)) + 3) & ~std::size_t{3});
            const auto count = std::min(size - offset, target - pending.size());
            pending.insert(pending.end(), bytes + offset, bytes + offset + count);
            offset += count;
            if (pending.size() < 4) continue;
            if (u16(pending.data()) >= 0x8000 ||
                (u16(pending.data()) < 0x4000 && (u16(pending.data() + 2) % 4))) invalid();
            const std::size_t complete_size = u16(pending.data()) < 0x4000 ?
                20 + u16(pending.data() + 2) :
                4 + ((std::size_t(u16(pending.data() + 2)) + 3) & ~std::size_t{3});
            if (pending.size() == complete_size) {
                validate_response(pending.data(), pending.size());
                output.insert(output.end(), pending.begin(), pending.end());
                pending.clear();
            }
        }
        return output;
    } catch (...) { failed = true; throw; }
}
void ProbeTurnResponses::finish() const { if (failed || !pending.empty()) invalid(); }
std::string probe_relay_alpn(const std::string &lease) {
    if (lease.size() != 64 || !std::all_of(lease.begin(), lease.end(), [](char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        })) throw std::runtime_error("Invalid probe relay lease identity");
    return "traverse-probe/" + lease;
}
bool forward_probe_tls(const ProbeTlsEndpoint &endpoint, int plain_fd,
                       const std::atomic<bool> &stopped,
                       const std::function<void()> &verified) {
    auto admitted=probe_target(endpoint);
    auto &storage=admitted.address;auto address_size=admitted.size;
    using Context = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;
    using Session = std::unique_ptr<SSL, decltype(&SSL_free)>;
    Context context(SSL_CTX_new(TLS_client_method()), SSL_CTX_free);
    if (!context || SSL_CTX_set_min_proto_version(context.get(), TLS1_2_VERSION) != 1 ||
        (endpoint.ca_file.empty() ? SSL_CTX_set_default_verify_paths(context.get()) :
            SSL_CTX_load_verify_locations(context.get(), endpoint.ca_file.c_str(), nullptr)) != 1)
        throw std::runtime_error("Cannot load probe TLS trust");
    SSL_CTX_set_verify(context.get(), SSL_VERIFY_PEER, nullptr);
    SSL_CTX_set_session_cache_mode(context.get(), SSL_SESS_CACHE_OFF);
    SSL_CTX_set_options(context.get(), SSL_OP_NO_TICKET);
    Session tls(SSL_new(context.get()), SSL_free);
    if (!tls) throw std::runtime_error("Cannot prepare probe TLS");
    in_addr identity4{}; in6_addr identity6{};
    if (inet_pton(AF_INET, endpoint.hostname.c_str(), &identity4) == 1 ||
        inet_pton(AF_INET6, endpoint.hostname.c_str(), &identity6) == 1) {
        if (X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(tls.get()), endpoint.hostname.c_str()) != 1)
            throw std::runtime_error("Cannot set probe TLS IP identity");
    } else if (SSL_set1_host(tls.get(), endpoint.hostname.c_str()) != 1 ||
               SSL_set_tlsext_host_name(tls.get(), endpoint.hostname.c_str()) != 1)
        throw std::runtime_error("Cannot set probe TLS hostname identity");
    X509_VERIFY_PARAM_set_hostflags(SSL_get0_param(tls.get()), X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    std::string alpn(1, static_cast<char>(endpoint.alpn.size())); alpn += endpoint.alpn;
    if (SSL_set_alpn_protos(tls.get(), reinterpret_cast<const unsigned char *>(alpn.data()), alpn.size()) != 0)
        throw std::runtime_error("Cannot set probe TLS ALPN");
    if (stopped) return false;
    Socket socket;
    socket.fd = ::socket(storage.ss_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (socket.fd < 0) throw std::runtime_error("Cannot open probe TLS socket");
    int immediate = 1;
    if (setsockopt(socket.fd, IPPROTO_TCP, TCP_NODELAY, &immediate, sizeof(immediate)))
        throw std::runtime_error("Cannot configure probe TLS socket");
    if (connect(socket.fd, reinterpret_cast<sockaddr *>(&storage), address_size) < 0) {
        if (errno != EINPROGRESS) throw std::runtime_error("Cannot connect probe TLS socket");
        if (!wait_socket(socket.fd, POLLOUT, stopped)) return false;
        int error = 0; socklen_t size = sizeof(error);
        if (getsockopt(socket.fd, SOL_SOCKET, SO_ERROR, &error, &size) || error)
            throw std::runtime_error("Cannot connect probe TLS socket");
    }
    if (SSL_set_fd(tls.get(), socket.fd) != 1) throw std::runtime_error("Cannot attach probe TLS socket");
    while (!stopped) {
        int result = SSL_connect(tls.get());
        if (result == 1) break;
        int error = SSL_get_error(tls.get(), result);
        if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE)
            throw std::runtime_error("Probe TLS identity or handshake failed");
        if (!wait_socket(socket.fd, error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT, stopped)) return false;
    }
    if (stopped) return false;
    const unsigned char *selected = nullptr; unsigned selected_size = 0;
    SSL_get0_alpn_selected(tls.get(), &selected, &selected_size);
    if (SSL_get_verify_result(tls.get()) != X509_V_OK || selected_size != endpoint.alpn.size() ||
        std::memcmp(selected, endpoint.alpn.data(), selected_size))
        throw std::runtime_error("Probe TLS identity or ALPN rejected");
    if (verified) verified();
    const int flags = fcntl(plain_fd, F_GETFL);
    if (flags < 0 || fcntl(plain_fd, F_SETFL, flags | O_NONBLOCK) < 0)
        throw std::runtime_error("Cannot prepare local probe relay socket");
    ProbeTurnResponses responses;
    TlsStreamTransform admission = [&](const unsigned char *bytes, std::size_t size, bool from_tls) {
        return from_tls ? responses.receive(bytes, size) : std::vector<unsigned char>(bytes, bytes + size);
    };
    TlsStreamBuffer outgoing;
    forward_tls_stream(tls.get(), socket.fd, plain_fd, stopped, outgoing, &admission);
    if (stopped) return false;
    responses.finish();
    return true;
}
struct ProbeTlsRelay::Impl {
    const ProbeTlsEndpoint endpoint;
    Socket listener;
    std::uint16_t bound_port = 0;
    std::atomic<bool> stopped{false};
    mutable std::mutex stats_mutex;
    ProbeTlsRelaySnapshot counts;
    std::mutex lifecycle;
    struct Connection {
        const int fd;
        std::atomic<bool> done{false};
        explicit Connection(int value):fd(value){}
        ~Connection(){close(fd);}
        void cancel(){shutdown(fd,SHUT_RDWR);}
    };
    struct Worker {std::shared_ptr<Connection> connection;std::thread thread;};
    std::vector<Worker> workers;
    std::thread acceptor;
    explicit Impl(ProbeTlsEndpoint value):endpoint(std::move(value)) {
        (void)probe_target(endpoint);
        listener.fd=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0);
        if(listener.fd<0)throw std::runtime_error("Cannot create private probe relay");
        int reuse=1;
        if(setsockopt(listener.fd,SOL_SOCKET,SO_REUSEADDR,&reuse,sizeof(reuse)))
            throw std::runtime_error("Cannot configure private probe relay");
        sockaddr_in local{};local.sin_family=AF_INET;local.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        if(bind(listener.fd,reinterpret_cast<sockaddr *>(&local),sizeof(local)) || listen(listener.fd,SOMAXCONN))
            throw std::runtime_error("Cannot bind private probe relay");
        socklen_t size=sizeof(local);
        if(getsockname(listener.fd,reinterpret_cast<sockaddr *>(&local),&size))
            throw std::runtime_error("Cannot inspect private probe relay");
        bound_port=ntohs(local.sin_port);
        acceptor=std::thread([this]{accept_loop();});
    }
    ~Impl(){stop();}
    void accept_loop() {
        while(!stopped) {
            for(auto it=workers.begin();it!=workers.end();) {
                if(it->connection->done){it->thread.join();it=workers.erase(it);}
                else ++it;
            }
            pollfd event{listener.fd,POLLIN,0};
            if(poll(&event,1,100)<=0 || !(event.revents&POLLIN))continue;
            int fd=accept4(listener.fd,nullptr,nullptr,SOCK_CLOEXEC|SOCK_NONBLOCK);
            if(fd<0)continue;
            {std::lock_guard lock(stats_mutex);++counts.started;}
            std::shared_ptr<Connection> connection;
            try {
                connection=std::make_shared<Connection>(fd);fd=-1;
                int immediate=1;
                if(setsockopt(connection->fd,IPPROTO_TCP,TCP_NODELAY,&immediate,sizeof(immediate)))
                    throw std::runtime_error("Cannot configure private probe relay stream");
                workers.push_back({connection,{}});
                workers.back().thread=std::thread([this,connection]{
                    try {forward_probe_tls(endpoint,connection->fd,stopped,[this]{std::lock_guard lock(stats_mutex);++counts.verified;});}
                    catch(...) {if(!stopped){std::lock_guard lock(stats_mutex);++counts.failed;}}
                    {std::lock_guard lock(stats_mutex);++counts.finished;}
                    connection->done=true;
                });
            } catch(...) {
                if(fd>=0)close(fd);
                if(!workers.empty() && workers.back().connection==connection && !workers.back().thread.joinable())workers.pop_back();
                if(connection)connection->cancel();
                std::lock_guard lock(stats_mutex);++counts.finished;if(!stopped)++counts.failed;
            }
        }
    }
    void stop() {
        std::lock_guard lock(lifecycle);
        if(stopped.exchange(true))return;
        shutdown(listener.fd,SHUT_RDWR);
        if(acceptor.joinable())acceptor.join();
        if(listener.fd>=0){close(listener.fd);listener.fd=-1;}
        for(const auto &worker:workers)worker.connection->cancel();
        for(auto &worker:workers)if(worker.thread.joinable())worker.thread.join();
        workers.clear();
    }
};
ProbeTlsRelay::ProbeTlsRelay(const ProbeTlsEndpoint &endpoint):impl(std::make_unique<Impl>(endpoint)){}
ProbeTlsRelay::~ProbeTlsRelay()=default;
std::uint16_t ProbeTlsRelay::port()const{return impl->bound_port;}
ProbeTlsRelaySnapshot ProbeTlsRelay::snapshot()const{std::lock_guard lock(impl->stats_mutex);return impl->counts;}
void ProbeTlsRelay::stop(){impl->stop();}
}
