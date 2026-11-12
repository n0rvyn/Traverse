#pragma once
#include <nlohmann/json.hpp>
#include <string>

namespace traverse {
enum class CertificateMode { Supplied, Automatic, Local };

// One typed contract for old supplied configurations and consented automatic
// state. Parsing performs no enrollment, filesystem writes or network calls.
struct CertificateSettings {
    CertificateMode mode = CertificateMode::Supplied;
    std::string certificate, private_key;
    std::string domain, directory, terms_url;
    bool terms_agreed = false;
    std::string api_trust_file, certificate_trust_file;

    static CertificateSettings parse(const nlohmann::json &config, bool standalone,
                                     const std::string &domain,
                                     const std::string &configuration_directory);
    std::string managed_state_directory(const std::string &data_home) const;
    std::string store_identity() const;
};
} // namespace traverse
