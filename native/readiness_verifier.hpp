#pragma once
#include "readiness_challenge.hpp"
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <vector>

namespace traverse {
// Private trusted caller protocol. Never expose this target configuration to
// unauthenticated/public registrations. One worker handles one explicit pin.
struct ReadinessTarget {
    std::string host, address, base_path, origin, ca_file;
    int port;
    // Omitted inherits HTTPS trust; an explicit empty value selects system roots.
    std::optional<std::string> relay_ca_file;
};
struct ReadinessVerification {
    ReadinessTarget target;
    ReadinessChallenge::Lease lease;
};
std::string canonical_readiness_address(const std::string &address);
std::vector<std::string> readiness_local_addresses(const std::string &listen,const std::string &advertised);
ReadinessTarget parse_readiness_target(const nlohmann::json &target);
ReadinessVerification parse_readiness_verification(const nlohmann::json &request);
ReadinessChallenge::Receipt parse_readiness_receipt(
    const nlohmann::json &response,const ReadinessChallenge::Lease &lease);
// Shared native media contract. Source evidence proves DTLS/nonce; observer
// evidence additionally requires an actually decoded video frame.
nlohmann::json validate_media_received(const nlohmann::json &event,
    const std::string &nonce,bool observer,const std::string &peer={});
nlohmann::json parse_media_receipt(const nlohmann::json &receipt,
    const ReadinessChallenge::Lease &lease,const std::string &mode,unsigned short observer_port);
void validate_media_exchange(const nlohmann::json &receipt,const nlohmann::json &source,
    const ReadinessChallenge::Lease &lease,const std::string &mode,
    unsigned short observer_port,unsigned short source_port);
// Stable failures contain no remote body, target credentials or exception text.
// Success carries a private receipt, not outside-vantage/media/UI readiness.
nlohmann::json verify_readiness(const ReadinessVerification &request);
}
