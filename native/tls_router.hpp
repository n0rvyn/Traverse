#pragma once
#include <memory>
#include <string>

namespace traverse {
struct TlsRouterConfig {
    std::string address = "127.0.0.1", certificate, private_key;
    unsigned short port = 0, http_port = 0, turn_port = 0;
};
// Fixed loopback backends; routing never uses a client-supplied destination.
class TlsRouter {
    struct Impl;
    std::unique_ptr<Impl> impl;

  public:
    explicit TlsRouter(const TlsRouterConfig &config);
    ~TlsRouter();
    TlsRouter(const TlsRouter &) = delete;
    TlsRouter &operator=(const TlsRouter &) = delete;
    unsigned short port() const;
    void stop();
};
} // namespace traverse
