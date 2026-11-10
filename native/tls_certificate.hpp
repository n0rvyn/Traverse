#pragma once
#include <cstdint>
#include <functional>
#include <memory>
#include <openssl/ssl.h>
#include <optional>
#include <string>

namespace traverse {
struct TlsCertificateConfig {
    std::string certificate, private_key, expected_host;
    std::optional<std::string> ca_file, ca_directory;
    // Enabled only by the automatic-mode router with its owned challenge broker.
    // Supplied-certificate callers keep strict startup by default.
    bool allow_initially_unavailable = false;
};
struct TlsCertificateContext {
    std::shared_ptr<SSL_CTX> ssl;
    std::string fingerprint;
    std::int64_t valid_from = 0, valid_until = 0;
    bool valid_now() const;
};
struct TlsCertificateStatus {
    std::uint64_t revision = 0;
    std::string fingerprint, error;
    std::int64_t valid_from = 0, valid_until = 0;
    bool available = false;
};
// Complete replacements are checked before publication. Connections retain an
// immutable context; renewal never changes a live SSL object's configuration.
class TlsCertificates {
    struct Impl;
    std::unique_ptr<Impl> impl;

  public:
    TlsCertificates(const TlsCertificateConfig &, std::function<void(SSL_CTX *)> configure);
    ~TlsCertificates();
    bool refresh(bool force = false);
    std::shared_ptr<const TlsCertificateContext> context() const;
    TlsCertificateStatus status() const;
};
// Per-instance owner-only snapshots. No certificate/key paths or credentials.
void write_tls_certificate_status(const std::string &path, const TlsCertificateStatus &status);
TlsCertificateStatus read_tls_certificate_status(const std::string &path, int expected_pid,
                                                 bool allow_unprovisioned = false);
} // namespace traverse
