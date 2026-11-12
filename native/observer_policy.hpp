#pragma once
#include "readiness_verifier.hpp"
#include <map>
#include <set>

namespace traverse {
struct ResolutionTarget {
    std::string host;
    std::set<std::string> allowed_addresses;
};
struct ObserverRegistration {
    std::string id,token;
    ReadinessTarget target;
    ResolutionTarget resolution;
    nlohmann::json verification(const std::string &address,const nlohmann::json &lease) const;
    nlohmann::json resolution_request() const;
};
struct ObserverConfiguration {
    std::string listen_address,certificate,private_key;
    int port;
    std::map<std::string,ObserverRegistration> registrations;
    static ObserverConfiguration parse(const nlohmann::json &configuration);
};
ResolutionTarget parse_resolution_request(const nlohmann::json &request);
nlohmann::json resolve_readiness_dns(const ResolutionTarget &target);
}
