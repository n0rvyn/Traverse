#pragma once
#include "readiness_challenge.hpp"
#include <nlohmann/json.hpp>
#include <string>

namespace traverse {
// Private trusted caller protocol. Never expose this target configuration to
// unauthenticated/public registrations. One worker handles one explicit pin.
struct ReadinessTarget {
    std::string host, address, base_path, origin, ca_file;
    int port;
};
struct ReadinessVerification {
    ReadinessTarget target;
    ReadinessChallenge::Lease lease;
};
std::string canonical_readiness_address(const std::string &address);
ReadinessTarget parse_readiness_target(const nlohmann::json &target);
ReadinessVerification parse_readiness_verification(const nlohmann::json &request);
ReadinessChallenge::Receipt parse_readiness_receipt(
    const nlohmann::json &response,const ReadinessChallenge::Lease &lease);
// Stable failures contain no remote body, target credentials or exception text.
// Success carries a private receipt, not outside-vantage/media/UI readiness.
nlohmann::json verify_readiness(const ReadinessVerification &request);
}
