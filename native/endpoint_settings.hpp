#pragma once
#include "certificate_settings.hpp"
#include "observer_settings.hpp"
#include <cstdint>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>

namespace traverse {
enum class EndpointMode { Legacy, Standalone };

// Pure configuration contract: no display, networking or private media initialization.
struct EndpointSettings {
    EndpointMode mode = EndpointMode::Standalone;
    std::string domain, origin, base_path = "/", display;
    CertificateSettings certificates;
    std::optional<ObserverSettings> observer;
    std::string listen_address = "0.0.0.0";
    std::uint16_t port = 443, media_port = 443;
    std::optional<std::uint16_t> listen_port;
    std::uint16_t turn_backend_port = 0;
    bool proxy_tls = false;

    std::uint16_t frontend_port() const { return listen_port.value_or(port); }

    static EndpointSettings parse(const nlohmann::json &config,
                                  const std::string &default_display = "",
                                  const std::string &configuration_directory = "");
    static std::string normalize_host(std::string host);
    static std::string normalize_base_path(const std::string &path);
    std::string public_url() const;
    std::string turns_url() const;
};
} // namespace traverse
