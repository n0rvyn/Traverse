#pragma once
#include "readiness_verifier.hpp"
#include <set>

namespace traverse {
struct ResolutionTarget {
    std::string host;
    std::set<std::string> allowed_addresses;
};
nlohmann::json resolve_readiness_dns(const ResolutionTarget &target);
// One strict contract shared by the producer and all authenticated consumers.
nlohmann::json validate_resolution_evidence(const nlohmann::json &value);
bool complete_resolution_evidence(const nlohmann::json &value);
namespace detail {
struct DnsAnswer {
    std::set<std::string> addresses;
    std::string terminal;
    bool alias=false;
};
DnsAnswer parse_dns_answer(const unsigned char *bytes,size_t size,int type,const std::string &host);
}
}
