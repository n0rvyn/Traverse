#include "readiness_challenge.hpp"
#include "common.hpp"
#include <openssl/sha.h>

namespace traverse {
ReadinessChallenge::ReadinessChallenge():instance(random_secret(16)) {}

ReadinessChallenge::Digest ReadinessChallenge::token_key(const std::string &token) {
    Digest key{};
    if(!SHA256(reinterpret_cast<const unsigned char *>(token.data()),token.size(),key.data()))
        throw std::runtime_error("Cannot authenticate readiness lease");
    return key;
}

bool ReadinessChallenge::valid_id(const std::string &id) {
    return id.size()==32 && id.find_first_not_of("0123456789abcdef")==std::string::npos;
}
ReadinessChallenge::Lease ReadinessChallenge::begin() {
    Lease lease;lease.instance=instance;lease.id=random_secret(16);
    lease.token=random_secret(32);lease.nonce=random_secret(32);
    auto result=store(std::move(lease),false);
    if(!result)throw std::runtime_error("Cannot create unique readiness lease");
    return *result;
}
std::optional<ReadinessChallenge::Lease> ReadinessChallenge::reserve(const std::string &id) {
    if(!valid_id(id))throw std::invalid_argument("Invalid readiness reservation ID");
    Lease lease;lease.instance=instance;lease.id=id;
    lease.token=random_secret(32);lease.nonce=random_secret(32);
    return store(std::move(lease),true);
}
std::optional<ReadinessChallenge::Lease> ReadinessChallenge::store(Lease lease,bool reserved) {
    auto key=token_key(lease.token);
    std::lock_guard lock(mutex);
    if(cancelled_ids.count(lease.id) || leases.count(lease.id))return std::nullopt;
    auto inserted=leases.emplace(lease.id,Entry{lease,std::nullopt,key,reserved});
    try {
        if(!token_index.emplace(key,lease.id).second)
            throw std::runtime_error("Cannot create unique readiness credential");
    } catch(...) {leases.erase(inserted.first);throw;}
    return lease;
}
bool ReadinessChallenge::cancel_reserved(const std::string &id) {
    if(!valid_id(id))throw std::invalid_argument("Invalid readiness reservation ID");
    std::lock_guard lock(mutex);
    auto found=leases.find(id);
    if(found!=leases.end() && !found->second.reserved)return false;
    // Insert denial before erasing authority. Allocation failure preserves the
    // live entry and reports failure; no late reserve can pass after success.
    cancelled_ids.insert(id);
    if(found!=leases.end()){token_index.erase(found->second.key);leases.erase(found);}
    return true;
}

bool ReadinessChallenge::valid_token(const std::string &token) const {
    // The protocol credential is exactly 32 random bytes encoded as hex.
    if(token.size()!=64)return false;
    auto key=token_key(token);
    std::lock_guard lock(mutex);
    auto indexed=token_index.find(key);
    if(indexed==token_index.end())return false;
    auto found=leases.find(indexed->second);
    return found!=leases.end() && !found->second.receipt &&
        equal_secret(found->second.lease.token,token);
}

std::optional<ReadinessChallenge::Receipt> ReadinessChallenge::consume(
    const std::string &id,const std::string &token,const std::string &nonce) {
    std::lock_guard lock(mutex);
    auto found=leases.find(id);
    if(found==leases.end() || found->second.receipt ||
       !equal_secret(found->second.lease.token,token) ||
       !equal_secret(found->second.lease.nonce,nonce))return std::nullopt;
    auto observed=std::chrono::duration_cast<std::chrono::milliseconds>(
        Clock::now().time_since_epoch()).count();
    Receipt receipt{instance,id,nonce,observed};
    found->second.receipt=receipt;
    return receipt;
}

std::optional<ReadinessChallenge::Snapshot> ReadinessChallenge::inspect(const std::string &id) const {
    std::lock_guard lock(mutex);
    auto found=leases.find(id);
    if(found==leases.end())return std::nullopt;
    return Snapshot{instance,id,found->second.receipt};
}

bool ReadinessChallenge::end(const std::string &id) {
    std::lock_guard lock(mutex);
    auto found=leases.find(id);
    if(found==leases.end())return false;
    if(found->second.reserved)cancelled_ids.insert(id);
    token_index.erase(found->second.key);leases.erase(found);return true;
}
}
