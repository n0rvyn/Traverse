#pragma once
#include <nlohmann/json.hpp>
#include <string>
namespace traverse {
// Shared producer/export-consumer boundary. Exactly one public certificate;
// no filesystem access, private keys, enrollment or trust-store modification.
nlohmann::json checked_local_authority(const std::string &pem,
    const nlohmann::json &metadata,const std::string &domain);
}
