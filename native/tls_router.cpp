#include "tls_router.hpp"
#include "bind_privilege.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <mutex>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <stdexcept>
#include <string_view>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace traverse {
namespace {
using Clock = std::chrono::steady_clock;
struct Socket {
    int fd = -1;
    explicit Socket(int value = -1) : fd(value) {}
    ~Socket() {
        if (fd >= 0)
            close(fd);
    }
    Socket(const Socket &) = delete;
    Socket &operator=(const Socket &) = delete;
};
struct Connection {
    Socket front, back;
    std::atomic<bool> done{false};
    std::mutex mutex;
    explicit Connection(int fd) : front(fd) {}
    void cancel() {
        std::lock_guard lock(mutex);
        shutdown(front.fd, SHUT_RDWR);
        if (back.fd >= 0)
            shutdown(back.fd, SHUT_RDWR);
    }
};
enum class Route { More, Http, Turn, Invalid };
Route classify(const unsigned char *data, size_t size) {
    static constexpr std::string_view methods[] = {
        "GET ", "HEAD ", "POST ", "PUT ", "DELETE ", "CONNECT ", "OPTIONS ", "TRACE ", "PATCH "};
    std::string_view prefix(reinterpret_cast<const char *>(data), size);
    for (auto method : methods) {
        if (size >= method.size() && prefix.substr(0, method.size()) == method)
            return Route::Http;
        if (size < method.size() && method.substr(0, size) == prefix)
            return Route::More;
    }
    if (size && (data[0] & 0xc0))
        return Route::Invalid;
    if (size < 20)
        return Route::More;
    return data[4] == 0x21 && data[5] == 0x12 && data[6] == 0xa4 && data[7] == 0x42 &&
                   (data[3] & 3) == 0
               ? Route::Turn
               : Route::Invalid;
}
struct Buffer {
    std::array<unsigned char, 16384> data{};
    size_t size = 0, offset = 0;
    bool empty() const {
        return offset == size;
    }
};
bool wait_for(int fd, short events, Clock::time_point deadline, const std::atomic<bool> &stopped) {
    while (!stopped && Clock::now() < deadline) {
        pollfd item{fd, events, 0};
        int result = poll(&item, 1, 100);
        if (result > 0)
            return (item.revents & (events | POLLHUP | POLLERR)) != 0;
        if (result < 0 && errno != EINTR)
            return false;
    }
    return false;
}
short ssl_wait(int error) {
    return error == SSL_ERROR_WANT_WRITE ? POLLOUT : POLLIN;
}
bool retryable(int error) {
    return error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE;
}
int alpn(SSL *, const unsigned char **out, unsigned char *outlen, const unsigned char *in,
         unsigned int length, void *) {
    static const unsigned char http[] = "http/1.1";
    for (unsigned i = 0; i < length;) {
        unsigned size = in[i++];
        if (size > length - i)
            return SSL_TLSEXT_ERR_ALERT_FATAL;
        if (size == sizeof(http) - 1 && !memcmp(in + i, http, size)) {
            *out = http;
            *outlen = size;
            return SSL_TLSEXT_ERR_OK;
        }
        i += size;
    }
    return SSL_TLSEXT_ERR_NOACK;
}
} // namespace

struct TlsRouter::Impl {
    TlsRouterConfig config;
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> context{nullptr, SSL_CTX_free};
    Socket listener;
    std::atomic<bool> stopped{false};
    unsigned short bound_port = 0;
    std::thread acceptor;
    struct Worker {
        std::shared_ptr<Connection> connection;
        std::thread thread;
    };
    std::vector<Worker> workers; // Only acceptor mutates this until it is joined.

    explicit Impl(const TlsRouterConfig &settings) : config(settings) {
        if (!config.http_port || !config.turn_port)
            throw std::runtime_error("Backend ports required");
        context.reset(SSL_CTX_new(TLS_server_method()));
        if (!context || !SSL_CTX_set_min_proto_version(context.get(), TLS1_2_VERSION) ||
            SSL_CTX_use_certificate_chain_file(context.get(), config.certificate.c_str()) != 1 ||
            SSL_CTX_use_PrivateKey_file(context.get(), config.private_key.c_str(),
                                        SSL_FILETYPE_PEM) != 1 ||
            SSL_CTX_check_private_key(context.get()) != 1)
            throw std::runtime_error("TLS certificate/key unavailable");
        SSL_CTX_set_alpn_select_cb(context.get(), alpn, nullptr);
        listener.fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (listener.fd < 0)
            throw std::runtime_error("Cannot create TLS listener");
        int reuse = 1;
        setsockopt(listener.fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(config.port);
        if (inet_pton(AF_INET, config.address.c_str(), &address.sin_addr) != 1 ||
            bind(listener.fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) ||
            listen(listener.fd, SOMAXCONN))
            throw std::runtime_error("Cannot bind TLS listener");
        socklen_t size = sizeof(address);
        if (getsockname(listener.fd, reinterpret_cast<sockaddr *>(&address), &size))
            throw std::runtime_error("Cannot inspect TLS listener");
        bound_port = ntohs(address.sin_port);
        drop_bind_privilege();
        acceptor = std::thread([this] { accept_loop(); });
    }
    ~Impl() {
        stop();
    }
    void stop() {
        if (stopped.exchange(true))
            return;
        shutdown(listener.fd, SHUT_RDWR);
        if (acceptor.joinable())
            acceptor.join();
        for (auto &worker : workers)
            worker.connection->cancel();
        for (auto &worker : workers)
            if (worker.thread.joinable())
                worker.thread.join();
        workers.clear();
    }
    void accept_loop() {
        while (!stopped) {
            for (auto it = workers.begin(); it != workers.end();) {
                if (it->connection->done) {
                    it->thread.join();
                    it = workers.erase(it);
                } else
                    ++it;
            }
            pollfd item{listener.fd, POLLIN, 0};
            int ready = poll(&item, 1, 100);
            if (ready <= 0 || !(item.revents & POLLIN))
                continue;
            int fd = accept4(listener.fd, nullptr, nullptr, SOCK_CLOEXEC | SOCK_NONBLOCK);
            if (fd < 0)
                continue;
            int immediate = 1;
            if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &immediate, sizeof(immediate))) {
                close(fd);
                continue;
            }
            auto connection = std::make_shared<Connection>(fd);
            try {
                workers.push_back({connection, {}});
                workers.back().thread = std::thread([this, connection] {
                    try {
                        serve(*connection);
                    } catch (...) { /* Close only this connection. */
                    }
                    connection->done = true;
                });
            } catch (...) {
                if (!workers.empty() && workers.back().connection == connection &&
                    !workers.back().thread.joinable())
                    workers.pop_back();
                connection->cancel();
            }
        }
    }
    void serve(Connection &connection) {
        auto deadline = Clock::now() + std::chrono::seconds(10);
        std::unique_ptr<SSL, decltype(&SSL_free)> ssl(SSL_new(context.get()), SSL_free);
        if (!ssl || SSL_set_fd(ssl.get(), connection.front.fd) != 1)
            return;
        SSL_set_mode(ssl.get(),
                     SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
        while (!stopped) {
            int result = SSL_accept(ssl.get());
            if (result == 1)
                break;
            int error = SSL_get_error(ssl.get(), result);
            if (!retryable(error) ||
                !wait_for(connection.front.fd, ssl_wait(error), deadline, stopped))
                return;
        }
        Buffer outgoing, incoming;
        Route route = Route::More;
        while (!stopped && route == Route::More) {
            size_t count = 0;
            int result = SSL_read_ex(ssl.get(), outgoing.data.data() + outgoing.size,
                                     20 - outgoing.size, &count);
            if (result == 1) {
                outgoing.size += count;
                route = classify(outgoing.data.data(), outgoing.size);
            } else {
                int error = SSL_get_error(ssl.get(), result);
                if (!retryable(error) ||
                    !wait_for(connection.front.fd, ssl_wait(error), deadline, stopped))
                    return;
            }
        }
        if (stopped || route == Route::Invalid)
            return;
        {
            std::lock_guard lock(connection.mutex);
            connection.back.fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        }
        if (connection.back.fd < 0)
            return;
        int immediate = 1;
        if (setsockopt(connection.back.fd, IPPROTO_TCP, TCP_NODELAY, &immediate, sizeof(immediate)))
            return;
        sockaddr_in backend{};
        backend.sin_family = AF_INET;
        backend.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        backend.sin_port = htons(route == Route::Http ? config.http_port : config.turn_port);
        if (connect(connection.back.fd, reinterpret_cast<sockaddr *>(&backend), sizeof(backend)) <
            0) {
            if (errno != EINPROGRESS || !wait_for(connection.back.fd, POLLOUT, deadline, stopped))
                return;
            int error = 0;
            socklen_t size = sizeof(error);
            if (getsockopt(connection.back.fd, SOL_SOCKET, SO_ERROR, &error, &size) || error)
                return;
        }
        bool front_eof = false, back_eof = false, back_write_closed = false;
        short read_wait = POLLIN, write_wait = POLLOUT;
        while (!stopped) {
            if (front_eof && outgoing.empty() && !back_write_closed) {
                shutdown(connection.back.fd, SHUT_WR);
                back_write_closed = true;
            }
            if (back_eof && incoming.empty()) {
                SSL_shutdown(ssl.get());
                return;
            }
            pollfd fds[2]{{connection.front.fd, 0, 0}, {connection.back.fd, 0, 0}};
            if (!front_eof && outgoing.empty())
                fds[0].events |= read_wait;
            if (!incoming.empty())
                fds[0].events |= write_wait;
            if (!back_eof && incoming.empty())
                fds[1].events |= POLLIN;
            if (!outgoing.empty())
                fds[1].events |= POLLOUT;
            bool pending = !front_eof && outgoing.empty() && SSL_pending(ssl.get()) > 0;
            int ready = poll(fds, 2, pending ? 0 : 100);
            if (ready < 0) {
                if (errno == EINTR)
                    continue;
                return;
            }
            if (!outgoing.empty() && (fds[1].revents & (POLLOUT | POLLHUP | POLLERR))) {
                ssize_t n = send(connection.back.fd, outgoing.data.data() + outgoing.offset,
                                 outgoing.size - outgoing.offset, MSG_NOSIGNAL);
                if (n > 0)
                    outgoing.offset += n;
                else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
                    return;
            }
            if (!front_eof && outgoing.empty() &&
                (pending || (fds[0].revents & (read_wait | POLLHUP | POLLERR)))) {
                size_t n = 0;
                int result = SSL_read_ex(ssl.get(), outgoing.data.data(), outgoing.data.size(), &n);
                if (result == 1) {
                    outgoing.offset = 0;
                    outgoing.size = n;
                    read_wait = POLLIN;
                } else {
                    int error = SSL_get_error(ssl.get(), result);
                    if (error == SSL_ERROR_ZERO_RETURN)
                        front_eof = true;
                    else if (retryable(error))
                        read_wait = ssl_wait(error);
                    else
                        return;
                }
            }
            if (!incoming.empty() && (fds[0].revents & (write_wait | POLLHUP | POLLERR))) {
                size_t n = 0;
                int result = SSL_write_ex(ssl.get(), incoming.data.data() + incoming.offset,
                                          incoming.size - incoming.offset, &n);
                if (result == 1) {
                    incoming.offset += n;
                    write_wait = POLLOUT;
                } else {
                    int error = SSL_get_error(ssl.get(), result);
                    if (retryable(error))
                        write_wait = ssl_wait(error);
                    else
                        return;
                }
            }
            if (!back_eof && incoming.empty() && (fds[1].revents & (POLLIN | POLLHUP | POLLERR))) {
                ssize_t n = recv(connection.back.fd, incoming.data.data(), incoming.data.size(), 0);
                if (n > 0) {
                    incoming.offset = 0;
                    incoming.size = n;
                } else if (!n)
                    back_eof = true;
                else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
                    return;
            }
        }
    }
};
TlsRouter::TlsRouter(const TlsRouterConfig &config) : impl(std::make_unique<Impl>(config)) {}
TlsRouter::~TlsRouter() = default;
unsigned short TlsRouter::port() const {
    return impl->bound_port;
}
void TlsRouter::stop() {
    impl->stop();
}
} // namespace traverse
