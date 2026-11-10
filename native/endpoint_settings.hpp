#pragma once
#include <cstdint>
#include <nlohmann/json.hpp>
#include <string>

namespace traverse {
enum class EndpointMode { Legacy, Standalone };

// Pure configuration contract: no display, networking or private media initialization.
struct EndpointSettings {
    EndpointMode mode = EndpointMode::Standalone;
    std::string domain, origin, base_path = "/", certificate, private_key, display;
    std::string listen_address = "0.0.0.0";
    std::uint16_t port = 443, media_port = 443;

    static EndpointSettings parse(const nlohmann::json &config,
                                  const std::string &default_display = "",
                                  const std::string &configuration_directory = "");
    static std::string normalize_host(std::string host);
    static std::string normalize_base_path(const std::string &path);
    std::string public_url() const;
    std::string turns_url() const;
};
} // namespace traverse
