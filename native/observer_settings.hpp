#pragma once
#include <cstdint>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>

namespace traverse {
struct ObserverSettings {
    std::string host,ca_file,registration_id,token_file;
    std::uint16_t port;
    std::optional<std::int64_t> timeout_ms;
    static ObserverSettings parse(const nlohmann::json &value,const std::string &configuration_directory);
    nlohmann::json agent_configuration() const;
};
// Only used for observer-enabled launcher settings. Authenticate and use this
// FD's content, never authorize a secret using a later stat of different data.
nlohmann::json secure_observer_configuration(const std::string &path);
std::string read_observer_credential(const std::string &path);
std::string read_observer_ca(const std::string &path);
}
