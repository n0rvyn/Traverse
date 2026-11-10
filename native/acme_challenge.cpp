#include "acme_challenge.hpp"
#include "endpoint_settings.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <filesystem>
#include <limits>
#include <mutex>
#include <set>
#include <nlohmann/json.hpp>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <poll.h>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace traverse {
namespace {
struct Descriptor {
    int fd = -1;
    explicit Descriptor(int value = -1) : fd(value) {}
    ~Descriptor() { if (fd >= 0) close(fd); }
    Descriptor(const Descriptor &) = delete;
    Descriptor &operator=(const Descriptor &) = delete;
};
void require(bool ok) {
    if (!ok) throw std::runtime_error("Cannot prepare certificate challenge");
}
std::string dns_domain(const std::string &input) {
    auto result = EndpointSettings::normalize_host(input);
    in_addr v4{};
    in6_addr v6{};
    if (inet_pton(AF_INET, result.c_str(), &v4) == 1 ||
        inet_pton(AF_INET6, result.c_str(), &v6) == 1)
        throw std::runtime_error("Certificate challenge requires a DNS domain");
    return result;
}
std::array<unsigned char, 32> decode_digest(const std::string &value) {
    if (value.size() != 43 ||
        value.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") != std::string::npos)
        throw std::runtime_error("Invalid certificate challenge digest");
    auto padded = value + "=";
    for (auto &c : padded) { if (c == '-') c = '+'; else if (c == '_') c = '/'; }
    std::array<unsigned char, 33> buffer{};
    require(EVP_DecodeBlock(buffer.data(), reinterpret_cast<const unsigned char *>(padded.data()),
                            static_cast<int>(padded.size())) == 33);
    std::array<unsigned char, 45> encoded{};
    require(EVP_EncodeBlock(encoded.data(), buffer.data(), 32) == 44);
    require(padded == reinterpret_cast<const char *>(encoded.data()));
    std::array<unsigned char, 32> result{};
    std::copy_n(buffer.begin(), result.size(), result.begin());
    return result;
}
int challenge_alpn(SSL *, const unsigned char **out, unsigned char *outlen,
                   const unsigned char *input, unsigned length, void *) {
    static const unsigned char protocol[] = "acme-tls/1";
    if (length != sizeof(protocol) || input[0] != sizeof(protocol) - 1 ||
        std::memcmp(input + 1, protocol, sizeof(protocol) - 1))
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    *out = protocol; *outlen = sizeof(protocol) - 1;
    return SSL_TLSEXT_ERR_OK;
}
std::shared_ptr<AcmeChallengeContext>
make_context(const std::string &domain, const std::array<unsigned char, 32> &digest,
             std::int64_t expiry, const std::function<void(SSL_CTX *)> &configure) {
    auto now = std::time(nullptr);
    if (now == static_cast<std::time_t>(-1) || expiry <= now ||
        static_cast<std::int64_t>(static_cast<std::time_t>(expiry)) != expiry)
        throw std::runtime_error("Invalid certificate challenge expiry");
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> generator(
        EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), EVP_PKEY_CTX_free);
    require(generator && EVP_PKEY_keygen_init(generator.get()) == 1 &&
            EVP_PKEY_CTX_set_ec_paramgen_curve_nid(generator.get(), NID_X9_62_prime256v1) == 1);
    EVP_PKEY *raw_key = nullptr;
    require(EVP_PKEY_keygen(generator.get(), &raw_key) == 1);
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(raw_key, EVP_PKEY_free);
    std::unique_ptr<X509, decltype(&X509_free)> cert(X509_new(), X509_free);
    require(cert && X509_set_version(cert.get(), 2) == 1);
    unsigned char serial_bytes[16];
    require(RAND_bytes(serial_bytes, sizeof(serial_bytes)) == 1);
    serial_bytes[0] = static_cast<unsigned char>((serial_bytes[0] & 0x7f) | 1);
    std::unique_ptr<BIGNUM, decltype(&BN_free)> serial(
        BN_bin2bn(serial_bytes, sizeof(serial_bytes), nullptr), BN_free);
    require(serial && BN_to_ASN1_INTEGER(serial.get(), X509_get_serialNumber(cert.get())));
    require(ASN1_TIME_set(X509_getm_notBefore(cert.get()), now) &&
            ASN1_TIME_set(X509_getm_notAfter(cert.get()), static_cast<std::time_t>(expiry)));
    require(X509_set_pubkey(cert.get(), key.get()) == 1);
    auto *subject = X509_get_subject_name(cert.get());
    static const unsigned char common_name[] = "Traverse certificate validation";
    require(X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, common_name, -1, -1, 0) == 1);
    require(X509_set_issuer_name(cert.get(), subject) == 1);
    std::unique_ptr<GENERAL_NAMES, decltype(&GENERAL_NAMES_free)> names(
        sk_GENERAL_NAME_new_null(), GENERAL_NAMES_free);
    std::unique_ptr<GENERAL_NAME, decltype(&GENERAL_NAME_free)> name(GENERAL_NAME_new(), GENERAL_NAME_free);
    std::unique_ptr<ASN1_IA5STRING, decltype(&ASN1_IA5STRING_free)> dns(ASN1_IA5STRING_new(), ASN1_IA5STRING_free);
    require(names && name && dns && ASN1_STRING_set(dns.get(), domain.data(), static_cast<int>(domain.size())) == 1);
    GENERAL_NAME_set0_value(name.get(), GEN_DNS, dns.release());
    require(sk_GENERAL_NAME_push(names.get(), name.get()) == 1); name.release();
    require(X509_add1_ext_i2d(cert.get(), NID_subject_alt_name, names.get(), 0, X509V3_ADD_DEFAULT) == 1);
    std::unique_ptr<ASN1_BIT_STRING, decltype(&ASN1_BIT_STRING_free)> usage(ASN1_BIT_STRING_new(), ASN1_BIT_STRING_free);
    require(usage && ASN1_BIT_STRING_set_bit(usage.get(), 0, 1) == 1 &&
            X509_add1_ext_i2d(cert.get(), NID_key_usage, usage.get(), 1, X509V3_ADD_DEFAULT) == 1);
    // extnValue wraps DER OCTET STRING, rather than the raw digest.
    std::array<unsigned char, 34> der{}; der[0] = 0x04; der[1] = 32;
    std::copy(digest.begin(), digest.end(), der.begin() + 2);
    std::unique_ptr<ASN1_OBJECT, decltype(&ASN1_OBJECT_free)> oid(
        OBJ_txt2obj("1.3.6.1.5.5.7.1.31", 1), ASN1_OBJECT_free);
    std::unique_ptr<ASN1_OCTET_STRING, decltype(&ASN1_OCTET_STRING_free)> value(
        ASN1_OCTET_STRING_new(), ASN1_OCTET_STRING_free);
    require(oid && value && ASN1_OCTET_STRING_set(value.get(), der.data(), der.size()) == 1);
    std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)> extension(
        X509_EXTENSION_create_by_OBJ(nullptr, oid.get(), 1, value.get()), X509_EXTENSION_free);
    require(extension && X509_add_ext(cert.get(), extension.get(), -1) == 1 &&
            X509_sign(cert.get(), key.get(), EVP_sha256()) > 0);
    auto result = std::make_shared<AcmeChallengeContext>();
    result->digest = digest; result->expires = expiry;
    require(RAND_bytes(result->session_id_context.data(), result->session_id_context.size()) == 1);
    result->ssl = {SSL_CTX_new(TLS_server_method()), SSL_CTX_free};
    require(result->ssl && SSL_CTX_set_min_proto_version(result->ssl.get(), TLS1_2_VERSION) == 1 &&
            SSL_CTX_use_certificate(result->ssl.get(), cert.get()) == 1 &&
            SSL_CTX_use_PrivateKey(result->ssl.get(), key.get()) == 1 &&
            SSL_CTX_check_private_key(result->ssl.get()) == 1 &&
            SSL_CTX_set_session_id_context(result->ssl.get(), result->session_id_context.data(), result->session_id_context.size()) == 1);
    SSL_CTX_set_options(result->ssl.get(), SSL_OP_NO_TICKET);
    SSL_CTX_set_session_cache_mode(result->ssl.get(), SSL_SESS_CACHE_OFF);
    require(SSL_CTX_set_num_tickets(result->ssl.get(), 0) == 1 &&
            SSL_CTX_set_max_early_data(result->ssl.get(), 0) == 1);
    SSL_CTX_set_alpn_select_cb(result->ssl.get(), challenge_alpn, nullptr);
    if (configure) configure(result->ssl.get());
    return result;
}
} // namespace

bool AcmeChallengeContext::valid_now() const {
    auto now = std::time(nullptr);
    return active.load() && now != static_cast<std::time_t>(-1) && now < expires;
}

struct AcmeChallenges::Impl {
    std::string path, host;
    std::function<void(SSL_CTX *)> configure;
    Descriptor listener;
    struct stat socket_identity{};
    bool owns_socket = false;
    std::atomic<bool> stopped{false};
    mutable std::mutex mutex;
    std::shared_ptr<AcmeChallengeContext> active;
    std::thread acceptor;
    struct Peer {
        Descriptor socket;
        std::atomic<bool> done{false};
        explicit Peer(int fd) : socket(fd) {}
    };
    struct Worker { std::shared_ptr<Peer> peer; std::thread thread; };
    std::vector<Worker> workers;

    Impl(const std::string &name, const std::string &domain, std::function<void(SSL_CTX *)> setup)
        : path(name), host(dns_domain(domain)), configure(std::move(setup)) {
        const auto parent = std::filesystem::path(path).parent_path();
        Descriptor directory(open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
        struct stat before{}, after{};
        if (!std::filesystem::path(path).is_absolute() || directory.fd < 0 ||
            fstat(directory.fd, &before) || before.st_uid != geteuid() || (before.st_mode & 0777) != 0700)
            throw std::runtime_error("Certificate challenge directory must be private and owned");
        sockaddr_un address{}; address.sun_family = AF_UNIX;
        if (path.size() >= sizeof(address.sun_path))
            throw std::runtime_error("Certificate challenge socket path is too long");
        std::memcpy(address.sun_path, path.c_str(), path.size() + 1);
        listener.fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (listener.fd < 0) throw std::runtime_error("Cannot create certificate challenge socket");
        if (bind(listener.fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)))
            throw std::runtime_error("Certificate challenge socket already exists or is unavailable");
        try {
            if (lstat(path.c_str(), &socket_identity) || !S_ISSOCK(socket_identity.st_mode) ||
                socket_identity.st_uid != geteuid())
                throw std::runtime_error("Certificate challenge socket ownership invalid");
            owns_socket = true;
            if (stat(parent.c_str(), &after) || before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
                chmod(path.c_str(), 0600) || listen(listener.fd, SOMAXCONN))
                throw std::runtime_error("Cannot prepare owned certificate challenge socket");
            acceptor = std::thread([this] { accept_loop(); });
        } catch (...) { remove_socket(); throw; }
    }
    ~Impl() { stop(); remove_socket(); }
    void remove_socket() {
        struct stat current{};
        if (owns_socket && !lstat(path.c_str(), &current) &&
            current.st_dev == socket_identity.st_dev && current.st_ino == socket_identity.st_ino &&
            current.st_uid == geteuid()) unlink(path.c_str());
        owns_socket = false;
    }
    bool transfer(int fd, void *buffer, size_t length, bool output) {
        auto *bytes = static_cast<unsigned char *>(buffer);
        while (length && !stopped) {
            pollfd event{fd, static_cast<short>(output ? POLLOUT : POLLIN), 0};
            int ready = poll(&event, 1, 100);
            if (ready < 0) { if (errno == EINTR) continue; return false; }
            if (!ready) continue;
            auto count = output ? send(fd, bytes, length, MSG_NOSIGNAL)
                                : recv(fd, bytes, length, 0);
            if (count > 0) { bytes += count; length -= static_cast<size_t>(count); }
            else if (!count || (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)) return false;
        }
        return length == 0;
    }
    bool reply(int fd, bool ready) {
        char success[] = "{\"ready\":true}", failure[] = "{\"ready\":false}";
        char *message = ready ? success : failure;
        auto size = std::strlen(message);
        auto length = htonl(static_cast<std::uint32_t>(size));
        return transfer(fd, &length, sizeof(length), true) && transfer(fd, message, size, true);
    }
    void serve(int fd) {
        std::shared_ptr<AcmeChallengeContext> lease;
        try {
            ucred peer{}; socklen_t size = sizeof(peer);
            if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &size) || size != sizeof(peer) || peer.uid != geteuid()) return;
            std::uint32_t size_be = 0;
            if (!transfer(fd, &size_be, sizeof(size_be), false)) return;
            auto length = ntohl(size_be);
            // Compact fixed-schema JSON: RFC DNS253 + base64url SHA25643 +
            // int64 expiry20 + literal field/syntax overhead, no arbitrary user cap.
            constexpr size_t max_frame = sizeof("{\"version\":1,\"domain\":\"\",\"sha256\":\"\",\"expires\":}") - 1 + 253 + 43 + 20;
            if (!length || length > max_frame) { reply(fd, false); return; }
            std::string text(length, '\0');
            if (!transfer(fd, text.data(), text.size(), false)) return;
            if (text.find_first_of(" \t\r\n") != std::string::npos) throw std::runtime_error("Invalid frame");
            std::set<std::string> keys;
            bool duplicate = false;
            auto value = nlohmann::json::parse(text,
                [&](int depth, nlohmann::json::parse_event_t event, nlohmann::json &item) {
                    if (depth == 1 && event == nlohmann::json::parse_event_t::key &&
                        !keys.insert(item.get<std::string>()).second) duplicate = true;
                    return true;
                });
            if (!value.is_object() || value.size() != 4 || !value.contains("version") ||
                duplicate ||
                !value.at("version").is_number_unsigned() || value.at("version") != 1 ||
                !value.at("domain").is_string() || !value.at("sha256").is_string() ||
                !value.at("expires").is_number_integer() ||
                (value.at("expires").is_number_unsigned() &&
                 value.at("expires").get<std::uint64_t>() > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())))
                throw std::runtime_error("Invalid lease");
            if (value.dump().size() != text.size()) throw std::runtime_error("Noncanonical lease encoding");
            if (dns_domain(value.at("domain").get<std::string>()) != host) throw std::runtime_error("Wrong domain");
            auto next = make_context(host, decode_digest(value.at("sha256").get<std::string>()),
                                     value.at("expires").get<std::int64_t>(), configure);
            {
                std::lock_guard lock(mutex);
                if (stopped || (active && active->valid_now())) throw std::runtime_error("Issuer lease already active");
                if (active) active->active = false;
                active = next; lease = std::move(next);
            }
            if (reply(fd, true)) {
                while (!stopped && lease->valid_now()) {
                    pollfd event{fd, POLLIN, 0};
                    int ready = poll(&event, 1, 100);
                    if (ready < 0) { if (errno == EINTR) continue; break; }
                    if (ready) break; // EOF or unexpected input ends this exact lease.
                }
            }
        } catch (...) { reply(fd, false); }
        if (lease) {
            std::lock_guard lock(mutex);
            lease->active = false;
            if (active == lease) active.reset();
        }
    }
    void accept_loop() {
        while (!stopped) {
            for (auto it = workers.begin(); it != workers.end();) {
                if (it->peer->done) { it->thread.join(); it = workers.erase(it); }
                else ++it;
            }
            pollfd event{listener.fd, POLLIN, 0};
            if (poll(&event, 1, 100) <= 0 || !(event.revents & POLLIN)) continue;
            int fd = accept4(listener.fd, nullptr, nullptr, SOCK_CLOEXEC | SOCK_NONBLOCK);
            if (fd < 0) continue;
            Descriptor pending(fd);
            std::shared_ptr<Peer> peer;
            try {
                peer = std::make_shared<Peer>(fd); pending.fd = -1;
                workers.push_back({peer, {}});
                workers.back().thread = std::thread([this, peer] { serve(peer->socket.fd); peer->done = true; });
            } catch (...) {
                if (!workers.empty() && workers.back().peer == peer && !workers.back().thread.joinable()) workers.pop_back();
            }
        }
    }
    void stop() {
        if (stopped.exchange(true)) return;
        shutdown(listener.fd, SHUT_RDWR);
        if (acceptor.joinable()) acceptor.join();
        for (auto &worker : workers) shutdown(worker.peer->socket.fd, SHUT_RDWR);
        for (auto &worker : workers) if (worker.thread.joinable()) worker.thread.join();
        workers.clear();
        std::lock_guard lock(mutex);
        if (active) active->active = false;
        active.reset();
        if (listener.fd >= 0) { close(listener.fd); listener.fd = -1; }
        remove_socket();
    }
};

AcmeChallenges::AcmeChallenges(const std::string &socket, const std::string &domain,
                               std::function<void(SSL_CTX *)> configure)
    : impl(std::make_unique<Impl>(socket, domain, std::move(configure))) {}
AcmeChallenges::~AcmeChallenges() = default;
std::shared_ptr<const AcmeChallengeContext> AcmeChallenges::current() const {
    std::lock_guard lock(impl->mutex);
    return impl->active && impl->active->valid_now() ? impl->active : nullptr;
}
const std::string &AcmeChallenges::domain() const { return impl->host; }
void AcmeChallenges::stop() { impl->stop(); }
} // namespace traverse
