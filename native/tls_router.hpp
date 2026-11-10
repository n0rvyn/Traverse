#pragma once
#include "tls_certificate.hpp"
#include <memory>
#include <string>

namespace traverse {
struct TlsRouterConfig {
    std::string address = "127.0.0.1", certificate, private_key;
    std::string expected_host;
    std::optional<std::string> ca_file, ca_directory;
    std::string acme_socket;
    bool allow_certificate_bootstrap = false;
    bool challenge_only = false;
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
    bool refresh_certificate(bool force = false);
    TlsCertificateStatus certificate_status() const;
    void stop();
};
} // namespace traverse
