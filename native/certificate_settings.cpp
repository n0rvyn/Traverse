#include "certificate_settings.hpp"
#include "endpoint_settings.hpp"
#include <arpa/inet.h>
#include <filesystem>
#include <iomanip>
#include <openssl/sha.h>
#include <set>
#include <sstream>
#include <stdexcept>

namespace traverse {
namespace {
using json = nlohmann::json;
std::string text(const json &value, const char *field, bool required = false) {
    if (!value.contains(field)) {
        if (required)
            throw std::runtime_error(std::string(field) + " is required");
        return {};
    }
    if (!value.at(field).is_string())
        throw std::runtime_error(std::string(field) + " must be a string");
    auto result = value.at(field).get<std::string>();
    if (result.find('\0') != std::string::npos)
        throw std::runtime_error("Invalid certificate setting text");
    return result;
}
void fields(const json &value, const std::set<std::string> &allowed) {
    for (auto it = value.begin(); it != value.end(); ++it)
        if (!allowed.count(it.key()))
            throw std::runtime_error("Unknown certificate setting: " + it.key());
}
std::string resolved(const std::string &value, bool standalone, const std::string &directory) {
    if (!standalone)
        return value;
    auto path = std::filesystem::path(value);
    if (path.is_relative()) {
        if (!std::filesystem::path(directory).is_absolute())
            throw std::runtime_error(
                "Relative TLS paths require an absolute configuration directory");
        path = std::filesystem::path(directory) / path;
    }
    return path.lexically_normal().string();
}
void ca_directory(const std::string &value) {
    if (value.rfind("https://", 0) != 0 || value.find('#') != std::string::npos ||
        value.find_first_of("\r\n\t ") != std::string::npos ||
        value.find('\\') != std::string::npos)
        throw std::runtime_error("CA directory must be an HTTPS address");
    auto authority = value.substr(8, value.find_first_of("/?", 8) - 8);
    if (authority.empty() || authority.find('@') != std::string::npos)
        throw std::runtime_error("Invalid CA authority");
    std::string host, port;
    if (authority.front() == '[') {
        auto end = authority.find(']');
        if (end == std::string::npos)
            throw std::runtime_error("Invalid CA authority");
        host = authority.substr(0, end + 1);
        if (end + 1 < authority.size()) {
            if (authority[end + 1] != ':')
                throw std::runtime_error("Invalid CA port");
            port = authority.substr(end + 2);
            if (port.empty())
                throw std::runtime_error("Invalid CA port");
        }
    } else {
        auto split = authority.find(':');
        host = authority.substr(0, split);
        if (split != std::string::npos) {
            port = authority.substr(split + 1);
            if (port.empty())
                throw std::runtime_error("Invalid CA port");
        }
    }
    EndpointSettings::normalize_host(host);
    if (!port.empty() && (port.find_first_not_of("0123456789") != std::string::npos ||
                          std::stoul(port) > 65535 || !std::stoul(port)))
        throw std::runtime_error("Invalid CA port");
}
void terms_reference(const std::string &value) {
    if (value.empty())
        return; // CA directories without a terms document.
    if (value.find_first_of("\r\n\t") != std::string::npos)
        throw std::runtime_error("Invalid CA terms reference");
    if (value.rfind("https://", 0) == 0) {
        ca_directory(value.substr(0, value.find('#')));
        return;
    }
    if (value.rfind("data:", 0) != 0 || value.find('#') != std::string::npos ||
        value.find_first_of("\r\n\t") != std::string::npos)
        throw std::runtime_error("Unsupported CA terms reference");
    auto comma = value.find(',');
    if (comma == std::string::npos)
        throw std::runtime_error("Invalid inline CA terms");
    auto header = value.substr(5, comma - 5);
    for (auto &c : header)
        if (c >= 'A' && c <= 'Z')
            c += 'a' - 'A';
    auto split = header.find(';');
    auto media = header.substr(0, split);
    if (!media.empty() && media != "text/plain")
        throw std::runtime_error("CA inline terms must be plain text");
    std::set<std::string> seen;
    while (split != std::string::npos) {
        auto next = header.find(';', split + 1);
        auto parameter = header.substr(split + 1, next - split - 1);
        auto name = parameter.substr(0, parameter.find('='));
        if (!seen.insert(name).second || (parameter != "base64" && parameter != "charset=utf-8" &&
                                          parameter != "charset=us-ascii"))
            throw std::runtime_error("Unsupported CA terms encoding");
        split = next;
    }
    // The cold helper validates decoded text/base64 before any CA/account work.
}
} // namespace

CertificateSettings CertificateSettings::parse(const json &config, bool standalone,
                                               const std::string &domain,
                                               const std::string &configuration_directory) {
    CertificateSettings result;
    result.domain = domain;
    if (config.contains("certificateSettings")) {
        const auto &options = config.at("certificateSettings");
        if (!standalone || !options.is_object())
            throw std::runtime_error("Versioned certificate settings required");
        auto mode = text(options, "mode", true);
        if (mode == "local") {
            fields(options, {"mode"});
            if (config.contains("certificate") || config.contains("privateKey"))
                throw std::runtime_error("Local and supplied certificate settings cannot be mixed");
            result.mode = CertificateMode::Local;
            in6_addr address{};
            if (inet_pton(AF_INET6, domain.c_str(), &address) == 1 && IN6_IS_ADDR_V4MAPPED(&address)) {
                char normalized[INET_ADDRSTRLEN];
                if (!inet_ntop(AF_INET, address.s6_addr + 12, normalized, sizeof(normalized)))
                    throw std::runtime_error("Cannot normalize local certificate address");
                result.domain = normalized;
            }
            return result;
        }
        if (mode == "automatic") {
            fields(options, {"mode", "directory", "termsURL", "termsAgreed", "apiTrustFile",
                             "certificateTrustFile"});
            if (config.contains("certificate") || config.contains("privateKey"))
                throw std::runtime_error(
                    "Automatic and supplied certificate settings cannot be mixed");
            in_addr v4{};
            in6_addr v6{};
            if (inet_pton(AF_INET, domain.c_str(), &v4) == 1 ||
                inet_pton(AF_INET6, domain.c_str(), &v6) == 1)
                throw std::runtime_error("Automatic certificates require a DNS domain");
            result.mode = CertificateMode::Automatic;
            result.directory = text(options, "directory", true);
            ca_directory(result.directory);
            result.terms_url = text(options, "termsURL", true);
            terms_reference(result.terms_url);
            if (!options.contains("termsAgreed") || !options.at("termsAgreed").is_boolean() ||
                !options.at("termsAgreed").get<bool>())
                throw std::runtime_error("CA terms approval required");
            result.terms_agreed = true;
            result.api_trust_file = text(options, "apiTrustFile");
            result.certificate_trust_file = text(options, "certificateTrustFile");
            for (const auto *path : {&result.api_trust_file, &result.certificate_trust_file})
                if (!path->empty() &&
                    (!std::filesystem::path(*path).is_absolute() ||
                     std::filesystem::path(*path).lexically_normal().string() != *path))
                    throw std::runtime_error("Absolute clean certificate trust paths required");
            return result;
        }
        if (mode != "supplied")
            throw std::runtime_error("Unknown certificate mode");
        fields(options, {"mode"});
    }
    result.certificate = text(config, "certificate");
    result.private_key = text(config, "privateKey");
    if (result.certificate.empty() || result.private_key.empty())
        throw std::runtime_error("certificate and privateKey are required");
    result.certificate = resolved(result.certificate, standalone, configuration_directory);
    result.private_key = resolved(result.private_key, standalone, configuration_directory);
    return result;
}

std::string CertificateSettings::managed_state_directory(const std::string &data_home) const {
    if (mode == CertificateMode::Supplied)
        throw std::logic_error("Supplied certificates have no managed state");
    auto path = std::filesystem::path(data_home);
    if (!path.is_absolute() || path.lexically_normal().string() != data_home)
        throw std::runtime_error("Absolute clean data directory required");
    // Retain the existing public-CA identity byte-for-byte. Local roots use a
    // distinct provider namespace and survive port/path changes.
    const auto identity = mode == CertificateMode::Local
                              ? nlohmann::json::array({"local-hostname:v1", domain}).dump()
                              : nlohmann::json::array({domain, directory}).dump();
    unsigned char digest[SHA256_DIGEST_LENGTH];
    if (!SHA256(reinterpret_cast<const unsigned char *>(identity.data()), identity.size(), digest))
        throw std::runtime_error("Cannot derive managed certificate identity");
    std::ostringstream encoded;
    encoded << std::hex << std::setfill('0');
    for (auto byte : digest)
        encoded << std::setw(2) << static_cast<unsigned>(byte);
    return (path / "traverse/certificates" / encoded.str()).string();
}
std::string CertificateSettings::store_identity() const {
    if (mode == CertificateMode::Supplied)
        throw std::logic_error("Supplied certificates have no managed identity");
    return mode == CertificateMode::Local ? "local-hostname:v1:" + domain : directory;
}
} // namespace traverse
