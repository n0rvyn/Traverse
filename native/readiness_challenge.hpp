#pragma once
#include <array>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <string>

namespace traverse {
// A reachability lease carries no capture, input or controller authority.
// Its trusted owner explicitly ends it; destruction revokes all leases.
// A receipt proves validated request arrival, not delivery of the response,
// the verifier's network vantage or any media/control readiness.
class ReadinessChallenge {
  public:
    struct Lease { std::string instance, id, token, nonce; };
    struct Receipt {
        std::string instance, id, nonce;
        std::int64_t observed_monotonic_ms;
    };
    struct Snapshot { std::string instance, id; std::optional<Receipt> receipt; };
    ReadinessChallenge();
    ReadinessChallenge(const ReadinessChallenge &)=delete;
    ReadinessChallenge &operator=(const ReadinessChallenge &)=delete;
    Lease begin();
    // Caller knows ID before dispatch. Cancellation denies late creation until
    // this service instance dies, even if a reserve reply is lost.
    static bool valid_id(const std::string &id);
    std::optional<Lease> reserve(const std::string &id);
    bool cancel_reserved(const std::string &id);
    bool valid_token(const std::string &token) const;
    std::optional<Receipt> consume(const std::string &id, const std::string &token,
                                   const std::string &nonce);
    std::optional<Snapshot> inspect(const std::string &id) const;
    bool end(const std::string &id);
  private:
    using Digest=std::array<unsigned char,32>;
    static Digest token_key(const std::string &token);
    struct Entry { Lease lease; std::optional<Receipt> receipt; Digest key; bool reserved=false; };
    std::optional<Lease> store(Lease lease,bool reserved);
    const std::string instance;
    mutable std::mutex mutex;
    std::map<std::string,Entry> leases;
    std::map<Digest,std::string> token_index;
    std::set<std::string> cancelled_ids;
};
}
