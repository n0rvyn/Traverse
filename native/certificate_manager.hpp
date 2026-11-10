#pragma once
#include "certificate_settings.hpp"
#include "tls_certificate.hpp"
#include <cstdint>
#include <filesystem>
#include <memory>
#include <nlohmann/json.hpp>

namespace traverse {
// Persisted scheduling uses the actual leaf validity and fingerprint. The
// injected wall clock and window selection make timing independently testable.
struct CertificateSchedule {
    std::string fingerprint;
    std::int64_t valid_from = 0, valid_until = 0, check_at = 0;
    double renew_at = 0, window_start = 0, window_end = 0;
    bool issuing = false, uncertain = false, admission_pending = false, consent_blocked = false;
    void material(const TlsCertificateStatus &, double now);
    void metadata(const nlohmann::json &, double now, double selected_window_time);
    nlohmann::json encode() const;
    static CertificateSchedule decode(const nlohmann::json &);
};

class CertificateManager {
    struct Impl;
    std::unique_ptr<Impl> impl;

  public:
    CertificateManager(const CertificateSettings &, const std::string &data_home,
                       const std::filesystem::path &issuer, const std::string &broker);
    ~CertificateManager();
    CertificateManager(const CertificateManager &) = delete;
    CertificateManager &operator=(const CertificateManager &) = delete;
    const std::string &bundle() const;
    const std::string &broker() const;
    TlsCertificateStatus application() const;
    void validation_route(bool available);
    void tick();
    void frontend(const TlsCertificateStatus &);
    nlohmann::json status() const;
    void stop();
};
} // namespace traverse
