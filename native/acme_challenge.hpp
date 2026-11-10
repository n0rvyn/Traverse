#pragma once
#include <array>
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <openssl/ssl.h>
#include <string>

namespace traverse {
struct AcmeChallengeContext {
    std::shared_ptr<SSL_CTX> ssl;
    std::array<unsigned char, 32> digest{};
    std::array<unsigned char, 32> session_id_context{};
    std::int64_t expires = 0;
    std::atomic<bool> active{true};
    bool valid_now() const;
};
// A private issuer keeps its authenticated connection open as the challenge
// lease. EOF, expiry and shutdown revoke it; challenge keys never leave memory.
class AcmeChallenges {
    struct Impl;
    std::unique_ptr<Impl> impl;

  public:
    AcmeChallenges(const std::string &socket, const std::string &domain,
                   std::function<void(SSL_CTX *)> configure = {});
    ~AcmeChallenges();
    AcmeChallenges(const AcmeChallenges &) = delete;
    AcmeChallenges &operator=(const AcmeChallenges &) = delete;
    std::shared_ptr<const AcmeChallengeContext> current() const;
    const std::string &domain() const;
    void stop();
};
} // namespace traverse
