#include "tls_certificate.hpp"
#include <arpa/inet.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <ctime>
#include <cstdlib>
#include <fcntl.h>
#include <filesystem>
#include <iomanip>
#include <mutex>
#include <limits>
#include <nlohmann/json.hpp>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <sstream>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>

namespace traverse {
namespace {
using Bio = std::unique_ptr<BIO, decltype(&BIO_free)>;
using Stamp = std::array<std::int64_t, 14>;
Stamp file_stamp(const TlsCertificateConfig &config) {
    Stamp result{};
    unsigned offset = 0;
    for (const auto &path : {config.certificate, config.private_key}) {
        struct stat item{};
        if (stat(path.c_str(), &item)) {
            result[offset] = -errno;
        } else {
            result[offset] = item.st_dev;
            result[offset + 1] = item.st_ino;
            result[offset + 2] = item.st_size;
            result[offset + 3] = item.st_mtim.tv_sec;
            result[offset + 4] = item.st_mtim.tv_nsec;
            result[offset + 5] = item.st_ctim.tv_sec;
            result[offset + 6] = item.st_ctim.tv_nsec;
        }
        offset += 7;
    }
    return result;
}
Bio pem_file(const std::string &path) {
    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0)
        throw std::runtime_error("Certificate or key file unavailable");
    struct stat item{};
    if (fstat(fd, &item) || !S_ISREG(item.st_mode)) {
        close(fd);
        throw std::runtime_error("Certificate and key must be regular files");
    }
    Bio result(BIO_new_fd(fd, BIO_CLOSE), BIO_free);
    if (!result) {
        close(fd);
        throw std::runtime_error("Cannot read certificate material");
    }
    return result;
}
std::int64_t utc(const ASN1_TIME *value) {
    std::tm fields{};
    if (!value || ASN1_TIME_to_tm(value, &fields) != 1)
        throw std::runtime_error("Certificate validity date unavailable");
    return timegm(&fields);
}
void restrict_dates(TlsCertificateContext &context, X509 *certificate) {
    context.valid_from = std::max(context.valid_from, utc(X509_get0_notBefore(certificate)));
    context.valid_until = std::min(context.valid_until, utc(X509_get0_notAfter(certificate)));
}
bool interval_valid(std::int64_t from, std::int64_t until) {
    auto now = std::time(nullptr);
    return now != static_cast<std::time_t>(-1) && now >= from && now < until;
}
std::shared_ptr<const TlsCertificateContext>
load(const TlsCertificateConfig &config, const std::function<void(SSL_CTX *)> &configure) {
    ERR_clear_error();
    auto result = std::make_shared<TlsCertificateContext>();
    result->ssl = {SSL_CTX_new(TLS_server_method()), SSL_CTX_free};
    if (!result->ssl || SSL_CTX_set_min_proto_version(result->ssl.get(), TLS1_2_VERSION) != 1)
        throw std::runtime_error("Cannot create TLS certificate context");
    configure(result->ssl.get());
    auto input = pem_file(config.certificate);
    std::unique_ptr<X509, decltype(&X509_free)> leaf(
        PEM_read_bio_X509_AUX(input.get(), nullptr, nullptr, nullptr), X509_free);
    if (!leaf || SSL_CTX_use_certificate(result->ssl.get(), leaf.get()) != 1)
        throw std::runtime_error("Certificate chain is not valid PEM");
    while (true) {
        X509 *next = PEM_read_bio_X509(input.get(), nullptr, nullptr, nullptr);
        if (!next) {
            auto error = ERR_peek_last_error();
            if (error && ERR_GET_REASON(error) != PEM_R_NO_START_LINE)
                throw std::runtime_error("Certificate chain is incomplete or malformed");
            ERR_clear_error();
            break;
        }
        if (SSL_CTX_add_extra_chain_cert(result->ssl.get(), next) != 1) {
            X509_free(next);
            throw std::runtime_error("Cannot load certificate chain");
        }
    }
    auto key_input = pem_file(config.private_key);
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(
        PEM_read_bio_PrivateKey(key_input.get(), nullptr,
                               +[](char *, int, int, void *) { return 0; }, nullptr),
        EVP_PKEY_free);
    if (!key || SSL_CTX_use_PrivateKey(result->ssl.get(), key.get()) != 1 ||
        SSL_CTX_check_private_key(result->ssl.get()) != 1)
        throw std::runtime_error("Certificate/key mismatch or unreadable unencrypted private key");

    result->valid_from = utc(X509_get0_notBefore(leaf.get()));
    result->valid_until = utc(X509_get0_notAfter(leaf.get()));
    if (!result->valid_now())
        throw std::runtime_error("Certificate is expired or not yet valid");
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned length = 0;
    if (X509_digest(leaf.get(), EVP_sha256(), digest, &length) != 1)
        throw std::runtime_error("Cannot identify certificate");
    std::ostringstream fingerprint;
    for (unsigned i = 0; i < length; ++i)
        fingerprint << std::hex << std::setw(2) << std::setfill('0') << unsigned(digest[i]);
    result->fingerprint = fingerprint.str();

    if (!config.expected_host.empty()) {
        unsigned char address[16];
        bool numeric = inet_pton(AF_INET, config.expected_host.c_str(), address) == 1 ||
                       inet_pton(AF_INET6, config.expected_host.c_str(), address) == 1;
        int matches = numeric ? X509_check_ip_asc(leaf.get(), config.expected_host.c_str(), 0)
                              : X509_check_host(leaf.get(), config.expected_host.c_str(), 0,
                                                X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS |
                                                    X509_CHECK_FLAG_NEVER_CHECK_SUBJECT,
                                                nullptr);
        if (matches != 1)
            throw std::runtime_error("Certificate does not match the configured domain");
        std::unique_ptr<X509_STORE, decltype(&X509_STORE_free)> store(X509_STORE_new(),
                                                                   X509_STORE_free);
        std::unique_ptr<X509_STORE_CTX, decltype(&X509_STORE_CTX_free)> verify(
            X509_STORE_CTX_new(), X509_STORE_CTX_free);
        if (!store || !verify)
            throw std::runtime_error("Cannot create certificate verification context");
        auto location = [](const std::optional<std::string> &explicit_path,
                           const char *environment, const char *compiled) {
            if (explicit_path) return *explicit_path;
            const char *value = getenv(environment);
            return std::string(value ? value : compiled);
        };
        auto file = location(config.ca_file, X509_get_default_cert_file_env(),
                             X509_get_default_cert_file());
        auto directory = location(config.ca_directory, X509_get_default_cert_dir_env(),
                                  X509_get_default_cert_dir());
        if (!file.empty() && X509_STORE_load_locations(store.get(), file.c_str(), nullptr) != 1) {
            if (config.ca_file || getenv(X509_get_default_cert_file_env()))
                throw std::runtime_error("Configured certificate trust file unavailable");
            ERR_clear_error();
        }
        if (!directory.empty() &&
            X509_STORE_load_locations(store.get(), nullptr, directory.c_str()) != 1)
            throw std::runtime_error("Certificate trust directory unavailable");
        STACK_OF(X509) *chain = nullptr;
        SSL_CTX_get_extra_chain_certs(result->ssl.get(), &chain);
        if (X509_STORE_CTX_init(verify.get(), store.get(), leaf.get(), chain) != 1 ||
            X509_STORE_CTX_set_purpose(verify.get(), X509_PURPOSE_SSL_SERVER) != 1)
            throw std::runtime_error("Cannot verify server certificate");
        X509_VERIFY_PARAM_set_auth_level(X509_STORE_CTX_get0_param(verify.get()),
                                        SSL_CTX_get_security_level(result->ssl.get()));
        if (X509_verify_cert(verify.get()) != 1)
            throw std::runtime_error(std::string("Certificate chain verification failed: ") +
                X509_verify_cert_error_string(X509_STORE_CTX_get_error(verify.get())));
        auto *verified = X509_STORE_CTX_get0_chain(verify.get());
        for (int i = 0; i < sk_X509_num(verified); ++i)
            restrict_dates(*result, sk_X509_value(verified, i));
    }
    if (!result->valid_now())
        throw std::runtime_error("Certificate chain is expired or not yet valid");
    ERR_clear_error();
    return result;
}
} // namespace

bool TlsCertificateContext::valid_now() const {
    return interval_valid(valid_from, valid_until);
}

struct TlsCertificates::Impl {
    TlsCertificateConfig config;
    std::function<void(SSL_CTX *)> configure;
    std::shared_ptr<const TlsCertificateContext> active;
    Stamp observed;
    std::chrono::steady_clock::time_point next_check{};
    mutable std::mutex mutex;
    std::uint64_t revision = 1;
    std::string error;
    Impl(const TlsCertificateConfig &settings, std::function<void(SSL_CTX *)> setup)
        : config(settings), configure(std::move(setup)), observed(file_stamp(settings)) {
        active = load(config, configure);
        if (file_stamp(config) != observed)
            throw std::runtime_error("Certificate files changed during initial loading");
    }
};
TlsCertificates::TlsCertificates(const TlsCertificateConfig &config,
                                 std::function<void(SSL_CTX *)> configure)
    : impl(std::make_unique<Impl>(config, std::move(configure))) {}
TlsCertificates::~TlsCertificates() = default;
bool TlsCertificates::refresh(bool force) {
    std::lock_guard lock(impl->mutex);
    auto now = std::chrono::steady_clock::now();
    if (!force && now < impl->next_check) return false;
    impl->next_check = now + std::chrono::seconds(1);
    auto changed = file_stamp(impl->config);
    if (!force && changed == impl->observed) return false;
    impl->observed = changed;
    try {
        auto next = load(impl->config, impl->configure);
        if (file_stamp(impl->config) != changed)
            throw std::runtime_error("Certificate files changed during renewal loading");
        std::atomic_store(&impl->active, std::move(next));
        ++impl->revision;
        impl->error.clear();
    } catch (const std::exception &error) {
        impl->error = error.what();
        ERR_clear_error();
    }
    return true;
}
std::shared_ptr<const TlsCertificateContext> TlsCertificates::context() const {
    auto active = std::atomic_load(&impl->active);
    return active && active->valid_now() ? active : nullptr;
}
TlsCertificateStatus TlsCertificates::status() const {
    std::lock_guard lock(impl->mutex);
    auto active = std::atomic_load(&impl->active);
    return {impl->revision, active->fingerprint, impl->error,
            active->valid_from, active->valid_until, active->valid_now()};
}

namespace {
struct Descriptor {
    int value;
    explicit Descriptor(int fd) : value(fd) {}
    ~Descriptor() { if (value >= 0) close(value); }
    Descriptor(const Descriptor &) = delete;
    Descriptor &operator=(const Descriptor &) = delete;
};
std::int64_t monotonic_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}
void status_parent(const std::filesystem::path &path) {
    struct stat parent{};
    if (!path.is_absolute() || stat(path.parent_path().c_str(), &parent) ||
        !S_ISDIR(parent.st_mode) || parent.st_uid != geteuid() || (parent.st_mode & 077))
        throw std::runtime_error("Certificate status directory must be private and owned");
}
bool status_mode(const struct stat &item) {
    return S_ISREG(item.st_mode) && item.st_uid == geteuid() &&
           (item.st_mode & 0777) == 0600 && item.st_nlink == 1;
}
} // namespace

void write_tls_certificate_status(const std::string &name, const TlsCertificateStatus &status) {
    std::filesystem::path path(name);
    status_parent(path);
    struct stat old{};
    if (!lstat(path.c_str(), &old)) {
        if (!status_mode(old))
            throw std::runtime_error("Certificate status file has unsafe ownership or permissions");
    } else if (errno != ENOENT) {
        throw std::runtime_error("Certificate status file unavailable");
    }
    auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    auto temporary = path.parent_path() /
        (".tls-status-" + std::to_string(getpid()) + "-" + std::to_string(now));
    Descriptor file(open(temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                         0600));
    if (file.value < 0)
        throw std::runtime_error("Cannot create certificate status snapshot");
    try {
        nlohmann::json snapshot = {{"schemaVersion", 1}, {"frontendPid", getpid()},
            {"observedMonotonicMs", monotonic_ms()}, {"revision", status.revision},
            {"fingerprint", status.fingerprint}, {"validFrom", status.valid_from},
            {"validUntil", status.valid_until}, {"available", status.available},
            {"reloadError", status.error}};
        auto data = snapshot.dump() + "\n";
        size_t written = 0;
        while (written < data.size()) {
            auto count = write(file.value, data.data() + written, data.size() - written);
            if (count > 0) written += count;
            else if (count < 0 && errno == EINTR) continue;
            else throw std::runtime_error("Cannot write certificate status snapshot");
        }
        if (fchmod(file.value, 0600) || rename(temporary.c_str(), path.c_str()))
            throw std::runtime_error("Cannot publish certificate status snapshot");
    } catch (...) {
        unlink(temporary.c_str());
        throw;
    }
}

TlsCertificateStatus read_tls_certificate_status(const std::string &name, int expected_pid) {
    if (expected_pid <= 0)
        throw std::runtime_error("Certificate frontend identity unavailable");
    std::filesystem::path path(name);
    status_parent(path);
    struct stat before{};
    if (lstat(path.c_str(), &before))
        throw std::runtime_error("Certificate status file is missing or unreadable");
    if (!status_mode(before))
        throw std::runtime_error("Certificate status file has unsafe ownership or permissions");
    Descriptor file(open(path.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW));
    if (file.value < 0)
        throw std::runtime_error("Certificate status file is missing or unreadable");
    struct stat item{};
    if (fstat(file.value, &item) || !status_mode(item))
        throw std::runtime_error("Certificate status file has unsafe ownership or permissions");
    std::string data;
    char bytes[4096];
    while (true) {
        auto count = read(file.value, bytes, sizeof(bytes));
        if (count > 0) data.append(bytes, count);
        else if (!count) break;
        else if (errno != EINTR)
            throw std::runtime_error("Certificate status file cannot be read");
    }
    try {
        auto value = nlohmann::json::parse(data);
        if (!value.is_object() || value.size() != 9 ||
            !value.at("schemaVersion").is_number_unsigned() || value.at("schemaVersion") != 1 ||
            !value.at("frontendPid").is_number_unsigned())
            throw std::runtime_error("Certificate status schema invalid");
        if (value.at("frontendPid").get<std::uint64_t>() !=
            static_cast<std::uint64_t>(expected_pid))
            throw std::runtime_error("Certificate status belongs to a different frontend");
        auto integer = [&](const char *key) {
            const auto &entry = value.at(key);
            if (!entry.is_number_integer() ||
                (entry.is_number_unsigned() && entry.get<std::uint64_t>() >
                    static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())))
                throw std::runtime_error("Certificate status integer invalid");
            return entry.get<std::int64_t>();
        };
        auto observed = integer("observedMonotonicMs"), now = monotonic_ms();
        // Same budget as child startup readiness; uncertainty does not revoke a
        // working session. The producer publishes an owner-only heartbeat each second.
        if (observed < 0 || observed > now || now - observed > 15000)
            throw std::runtime_error("Certificate status is stale");
        if (!value.at("revision").is_number_unsigned() ||
            !value.at("revision").get<std::uint64_t>() ||
            !value.at("fingerprint").is_string() || !value.at("reloadError").is_string() ||
            !value.at("available").is_boolean())
            throw std::runtime_error("Certificate status fields invalid");
        auto fingerprint = value.at("fingerprint").get<std::string>();
        if (fingerprint.size() != 64 ||
            fingerprint.find_first_not_of("0123456789abcdef") != std::string::npos)
            throw std::runtime_error("Certificate status fingerprint invalid");
        auto from = integer("validFrom"), until = integer("validUntil");
        if (from >= until)
            throw std::runtime_error("Certificate status validity invalid");
        return {value.at("revision").get<std::uint64_t>(), fingerprint,
                value.at("reloadError").get<std::string>(), from, until,
                value.at("available").get<bool>() && interval_valid(from, until)};
    } catch (const nlohmann::json::exception &) {
        throw std::runtime_error("Certificate status JSON invalid");
    }
}
} // namespace traverse
