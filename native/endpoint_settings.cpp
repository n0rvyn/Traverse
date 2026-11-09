#include "endpoint_settings.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <filesystem>
#include <regex>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace traverse {
namespace {
using json = nlohmann::json;
std::uint16_t port_value(const json &config, const char *key, unsigned fallback) {
    if (!config.contains(key))
        return fallback;
    const auto &value = config.at(key);
    if (!value.is_number_integer())
        throw std::runtime_error(std::string(key) + " must be an integer");
    if (value.is_number_unsigned() && value.get<unsigned long long>() > 65535)
        throw std::runtime_error(std::string(key) + " is out of range");
    auto number = value.get<long long>();
    if (number < 1 || number > 65535)
        throw std::runtime_error(std::string(key) + " must be between 1 and 65535");
    return static_cast<std::uint16_t>(number);
}
std::string text(const json &config, const char *key, const std::string &fallback = "") {
    if (!config.contains(key))
        return fallback;
    if (!config.at(key).is_string())
        throw std::runtime_error(std::string(key) + " must be a string");
    auto value = config.at(key).get<std::string>();
    if (value.find('\0') != std::string::npos)
        throw std::runtime_error(std::string(key) + " contains a null character");
    return value;
}
void fields(const json &config, const std::vector<std::string> &allowed) {
    for (auto it = config.begin(); it != config.end(); ++it)
        if (std::find(allowed.begin(), allowed.end(), it.key()) == allowed.end())
            throw std::runtime_error("Unknown configuration field: " + it.key());
}
std::string canonical_host(std::string host) {
    if (host.empty())
        throw std::runtime_error("domain is required");
    bool bracketed = host.front() == '[' && host.back() == ']';
    if (bracketed)
        host = host.substr(1, host.size() - 2);
    if (host.empty())
        throw std::runtime_error("Invalid domain or IP address");
    in_addr ipv4{};
    in6_addr ipv6{};
    std::array<char, INET6_ADDRSTRLEN> output{};
    if (!bracketed && inet_pton(AF_INET, host.c_str(), &ipv4) == 1) {
        inet_ntop(AF_INET, &ipv4, output.data(), output.size());
        return output.data();
    }
    if (inet_pton(AF_INET6, host.c_str(), &ipv6) == 1) {
        inet_ntop(AF_INET6, &ipv6, output.data(), output.size());
        return output.data();
    }
    if (bracketed)
        throw std::runtime_error("Brackets require an IPv6 address");
    if (host.back() == '.')
        host.pop_back();
    if (host.empty() || host.back() == '.' || host.size() > 253 ||
        host.find_first_not_of("0123456789.") == std::string::npos)
        throw std::runtime_error("Invalid domain or IP address");
    size_t start = 0;
    while (start < host.size()) {
        auto end = host.find('.', start);
        if (end == std::string::npos)
            end = host.size();
        auto length = end - start;
        if (!length || length > 63 || host[start] == '-' || host[end - 1] == '-')
            throw std::runtime_error("Invalid domain label");
        for (size_t i = start; i < end; ++i) {
            auto &c = host[i];
            if (c >= 'A' && c <= 'Z')
                c += 'a' - 'A';
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'))
                throw std::runtime_error(
                    "domain must be an ASCII hostname or IP without scheme, port or path");
        }
        start = end + 1;
    }
    auto last =
        host.substr(host.find_last_of('.') == std::string::npos ? 0 : host.find_last_of('.') + 1);
    if (last.find_first_not_of("0123456789") == std::string::npos ||
        (last.rfind("0x", 0) == 0 &&
         last.substr(2).find_first_not_of("0123456789abcdef") == std::string::npos))
        throw std::runtime_error(
            "Domain would be interpreted as a noncanonical IPv4 address by Chrome");
    return host;
}
std::string uri_host(const std::string &host) {
    return host.find(':') == std::string::npos ? host : "[" + host + "]";
}
bool chrome_restricted(unsigned port) {
    // Chromium net/base/port_util.cc kRestrictedPorts, checked 2026-11-09.
    // https://chromium.googlesource.com/chromium/src/+/refs/heads/main/net/base/port_util.cc
    static constexpr unsigned ports[] = {
        1,    7,    9,    11,   13,   15,   17,   19,   20,   21,   22,   23,   25,   37,
        42,   43,   53,   69,   77,   79,   87,   95,   101,  102,  103,  104,  109,  110,
        111,  113,  115,  117,  119,  123,  135,  137,  139,  143,  161,  179,  389,  427,
        465,  512,  513,  514,  515,  526,  530,  531,  532,  540,  548,  554,  556,  563,
        587,  601,  636,  989,  990,  993,  995,  1719, 1720, 1723, 2049, 3659, 4045, 5060,
        5061, 6000, 6566, 6665, 6666, 6667, 6668, 6669, 6697, 10080};
    return std::find(std::begin(ports), std::end(ports), port) != std::end(ports);
}
} // namespace

std::string EndpointSettings::normalize_base_path(const std::string &path) {
    if (path.empty() || path.front() != '/')
        throw std::runtime_error("basePath must start with /");
    if (path == "/")
        return path;
    std::string result = path;
    if (result.back() != '/')
        result += '/';
    size_t start = 1;
    while (start < result.size()) {
        auto end = result.find('/', start);
        auto part = std::string_view(result).substr(start, end - start);
        if (part.empty() || part == "." || part == "..")
            throw std::runtime_error("Invalid basePath segment");
        for (unsigned char c : part)
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                  c == '-' || c == '_' || c == '.' || c == '~'))
                throw std::runtime_error("basePath must use unencoded URL path segments");
        start = end + 1;
    }
    return result;
}

EndpointSettings EndpointSettings::parse(const json &config, const std::string &default_display,
                                         const std::string &configuration_directory) {
    if (!config.is_object())
        throw std::runtime_error("Configuration must be a JSON object");
    EndpointSettings settings;
    if (!config.contains("schemaVersion")) {
        settings.mode = EndpointMode::Legacy;
        fields(config, {"origin", "certificate", "privateKey", "display", "httpsPort", "mediaPort",
                        "listenAddress"});
        settings.origin = text(config, "origin");
        std::smatch parts;
        if (!std::regex_match(
                settings.origin, parts,
                std::regex(
                    R"(^https://(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9][A-Za-z0-9.-]*)(?::([0-9]+))?$)")))
            throw std::runtime_error("Invalid HTTPS origin hostname/port");
        settings.domain = parts[1].str();
        settings.port = port_value(config, "httpsPort", 8443);
        settings.media_port = port_value(config, "mediaPort", 50000);
        auto public_port = parts[2].matched ? std::stoull(parts[2].str()) : 443;
        if (public_port != settings.port)
            throw std::runtime_error("Standalone HTTPS origin port must match httpsPort");
        if (settings.port == settings.media_port)
            throw std::runtime_error("Legacy HTTPS and passive ICE-TCP need separate TCP ports; "
                                     "use schemaVersion 1 for one port");
    } else {
        if (!config["schemaVersion"].is_number_integer() || config["schemaVersion"] != 1)
            throw std::runtime_error("Unsupported schemaVersion");
        fields(config, {"schemaVersion", "domain", "port", "basePath", "certificate", "privateKey",
                        "display", "listenAddress"});
        settings.domain = canonical_host(text(config, "domain"));
        settings.port = port_value(config, "port", 443);
        if (chrome_restricted(settings.port))
            throw std::runtime_error("Chrome blocks this HTTPS port; choose another port");
        settings.media_port = settings.port;
        settings.base_path = normalize_base_path(text(config, "basePath", "/"));
        settings.origin = "https://" + uri_host(settings.domain) +
                          (settings.port == 443 ? "" : ":" + std::to_string(settings.port));
    }
    settings.certificate = text(config, "certificate");
    settings.private_key = text(config, "privateKey");
    if (settings.certificate.empty() || settings.private_key.empty())
        throw std::runtime_error("certificate and privateKey are required");
    if (settings.mode == EndpointMode::Standalone) {
        for (auto *value : {&settings.certificate, &settings.private_key}) {
            auto path = std::filesystem::path(*value);
            if (path.is_relative()) {
                auto directory = std::filesystem::path(configuration_directory);
                if (!directory.is_absolute())
                    throw std::runtime_error(
                        "Relative TLS paths require an absolute configuration directory");
                path = directory / path;
            }
            *value = path.lexically_normal().string();
        }
    }
    settings.display = text(config, "display", default_display);
    settings.listen_address = text(config, "listenAddress", "0.0.0.0");
    if (settings.mode == EndpointMode::Standalone) {
        in_addr v4{};
        in6_addr v6{};
        if (inet_pton(AF_INET, settings.listen_address.c_str(), &v4) != 1 &&
            inet_pton(AF_INET6, settings.listen_address.c_str(), &v6) != 1)
            throw std::runtime_error("listenAddress must be a numeric IP address");
    }
    return settings;
}
std::string EndpointSettings::public_url() const {
    return mode == EndpointMode::Legacy ? origin : origin + base_path;
}
std::string EndpointSettings::turns_url() const {
    if (mode == EndpointMode::Legacy)
        throw std::logic_error("Legacy endpoint has no bundled TURN address");
    auto host = domain;
    if (!host.empty() && host.front() == '[' && host.back() == ']')
        host = host.substr(1, host.size() - 2);
    return "turns:" + uri_host(host) + ":" + std::to_string(port) + "?transport=tcp";
}
} // namespace traverse
