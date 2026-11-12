#include "certificate_manager.hpp"
#include "child.hpp"
#include "local_authority.hpp"
#include <cmath>
#include <ctime>
#include <iomanip>
#include <limits>
#include <openssl/pem.h>
#include <set>
#include <sys/file.h>
#include <sys/inotify.h>
#include <utility>

namespace traverse {
namespace {
using json = nlohmann::json;
constexpr std::int64_t metadata_interval = 6 * 60 * 60; // RFC9773 long-term error fallback.
std::int64_t integer(const json &value, const char *name) {
    const auto &field = value.at(name);
    if (!field.is_number_integer() ||
        (field.is_number_unsigned() && field.get<std::uint64_t>() > std::uint64_t(INT64_MAX)))
        throw std::runtime_error("Invalid certificate timing metadata");
    return field.get<std::int64_t>();
}
bool fingerprint_valid(const std::string &value) {
    return value.size() == 64 && value.find_first_not_of("0123456789abcdef") == std::string::npos;
}
void only(const json &value, const std::set<std::string> &fields) {
    if (!value.is_object())
        throw std::runtime_error("Invalid certificate state schema");
    for (auto it = value.begin(); it != value.end(); ++it)
        if (!fields.count(it.key()))
            throw std::runtime_error("Invalid certificate state schema");
}
double current_time() {
    auto now =
        std::chrono::duration<double>(std::chrono::system_clock::now().time_since_epoch()).count();
    if (!std::isfinite(now) || now < 0)
        throw std::runtime_error("Certificate clock unavailable");
    return now;
}
double instant(const json &value, const char *name) {
    const auto &field = value.at(name);
    if (!field.is_number())
        throw std::runtime_error("Invalid certificate schedule time");
    auto number = field.get<double>();
    if (!std::isfinite(number) || number < 0 || number > 253402300799.0)
        throw std::runtime_error("Invalid certificate schedule time");
    return number;
}
double precise_time(const json &value, const char *name) {
    const auto text = value.at(name).get<std::string>();
    if (text.size() < 20 || text.back() != 'Z')
        throw std::runtime_error("Invalid precise renewal time");
    std::tm fields{};
    std::istringstream input(text.substr(0, 19));
    input >> std::get_time(&fields, "%Y-%m-%dT%H:%M:%S");
    if (input.fail() || !input.eof())
        throw std::runtime_error("Invalid precise renewal time");
    auto seconds = timegm(&fields);
    std::tm verified{};
    char canonical[32];
    if (!gmtime_r(&seconds, &verified) ||
        !std::strftime(canonical, sizeof(canonical), "%Y-%m-%dT%H:%M:%S", &verified) ||
        text.substr(0, 19) != canonical)
        throw std::runtime_error("Invalid precise renewal calendar time");
    double fraction = 0, scale = .1;
    if (text.size() != 20) {
        if (text[19] != '.' || text.size() == 21 || text.size() > 30)
            throw std::runtime_error("Invalid precise renewal fraction");
        for (size_t i = 20; i + 1 < text.size(); ++i) {
            if (text[i] < '0' || text[i] > '9')
                throw std::runtime_error("Invalid precise renewal fraction");
            fraction += (text[i] - '0') * scale;
            scale *= .1;
        }
    }
    auto result = static_cast<double>(seconds) + fraction;
    if (result < 0 || result > 253402300799.0)
        throw std::runtime_error("Invalid precise renewal time");
    return result;
}
std::pair<double, double> renewal_window(const json &metadata) {
    if (metadata.contains("windowStartPrecise") || metadata.contains("windowEndPrecise"))
        return {precise_time(metadata, "windowStartPrecise"),
                precise_time(metadata, "windowEndPrecise")};
    return {static_cast<double>(integer(metadata, "windowStart")),
            static_cast<double>(integer(metadata, "windowEnd"))};
}
// Leaf expiry is bounded by the X509 time representation, well below int64.
void dates(std::int64_t from, std::int64_t until) {
    if (from < 0 || until <= from || until > 253402300799LL)
        throw std::runtime_error("Invalid certificate validity metadata");
}
void secure_directory(const std::filesystem::path &path, bool private_owner) {
    struct stat info{};
    if (lstat(path.c_str(), &info) || !S_ISDIR(info.st_mode) ||
        ((info.st_mode & 0022) && !(info.st_mode & S_ISVTX)) ||
        (private_owner && (info.st_uid != getuid() || (info.st_mode & 0777) != 0700)))
        throw std::runtime_error("Unsafe managed certificate directory");
}
void directories(const std::filesystem::path &path) {
    std::filesystem::path current = "/";
    for (const auto &part : path.relative_path()) {
        current /= part;
        if (mkdir(current.c_str(), 0700) && errno != EEXIST)
            throw std::runtime_error("Cannot create managed certificate directory");
        secure_directory(current, false);
    }
}
struct Descriptor {
    int fd = -1;
    explicit Descriptor(int value) : fd(value) {}
    ~Descriptor() {
        if (fd >= 0)
            close(fd);
    }
};
std::optional<std::string> read_private(const std::filesystem::path &path) {
    struct stat before{}, after{};
    if (lstat(path.c_str(), &before)) {
        if (errno == ENOENT)
            return std::nullopt;
        throw std::runtime_error("Cannot inspect managed certificate state");
    }
    if (!S_ISREG(before.st_mode) || before.st_uid != getuid() || (before.st_mode & 0777) != 0600)
        throw std::runtime_error("Unsafe managed certificate state");
    Descriptor input(open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK));
    if (input.fd < 0 || fstat(input.fd, &after) || before.st_dev != after.st_dev ||
        before.st_ino != after.st_ino)
        throw std::runtime_error("Managed certificate state changed");
    std::string data;
    char bytes[4096];
    while (true) {
        auto count = read(input.fd, bytes, sizeof(bytes));
        if (count > 0) {
            data.append(bytes, count);
            continue;
        }
        if (!count)
            return data;
        if (errno != EINTR)
            throw std::runtime_error("Cannot read managed certificate state");
    }
}
void atomic_private(const std::filesystem::path &path, const std::string &data) {
    auto temporary = path.parent_path() / (".manager-pending-" + random_secret(16));
    Descriptor output(
        open(temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600));
    if (output.fd < 0)
        throw std::runtime_error("Cannot create certificate schedule");
    try {
        size_t offset = 0;
        while (offset < data.size()) {
            auto count = write(output.fd, data.data() + offset, data.size() - offset);
            if (count < 0 && errno == EINTR)
                continue;
            if (count <= 0)
                throw std::runtime_error("Cannot write certificate schedule");
            offset += count;
        }
        if (fsync(output.fd) || rename(temporary.c_str(), path.c_str()))
            throw std::runtime_error("Cannot publish certificate schedule");
        Descriptor directory(
            open(path.parent_path().c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
        if (directory.fd < 0 || fsync(directory.fd))
            throw std::runtime_error("Certificate schedule durability uncertain");
    } catch (...) {
        unlink(temporary.c_str());
        throw;
    }
}
} // namespace

void CertificateSchedule::material(const TlsCertificateStatus &certificate, double now) {
    if (!certificate.available || !fingerprint_valid(certificate.fingerprint))
        throw std::runtime_error("Current certificate required for scheduling");
    dates(certificate.valid_from, certificate.valid_until);
    if (fingerprint == certificate.fingerprint && valid_from == certificate.valid_from &&
        valid_until == certificate.valid_until)
        return;
    if (fingerprint == certificate.fingerprint) {
        valid_from = certificate.valid_from;
        valid_until = certificate.valid_until;
        renew_at = std::min(renew_at,
                            static_cast<double>(valid_from + (valid_until - valid_from) * 2 / 3));
        check_at = std::min(check_at, static_cast<std::int64_t>(now));
        return;
    }
    fingerprint = certificate.fingerprint;
    valid_from = certificate.valid_from;
    valid_until = certificate.valid_until;
    renew_at = valid_from + (valid_until - valid_from) * 2 / 3;
    check_at = now;
    window_start = window_end = 0;
    issuing = false;
    uncertain = false;
    admission_pending = false;
}
void CertificateSchedule::metadata(const json &metadata, double now, double selected) {
    if (metadata.at("material") != "current" || metadata.at("fingerprint") != fingerprint ||
        integer(metadata, "validFrom") > valid_from ||
        integer(metadata, "validUntil") < valid_until)
        throw std::runtime_error("Renewal metadata does not match active material");
    const auto ari = metadata.at("ari").get<std::string>();
    if (ari == "valid") {
        auto [first, last] = renewal_window(metadata);
        if (first < 0 || first >= last || last > 253402300799LL)
            throw std::runtime_error("Invalid renewal window");
        if (first != window_start || last != window_end) {
            if (selected < first || selected >= last)
                throw std::runtime_error("Invalid selected renewal time");
            renew_at = selected;
            window_start = first;
            window_end = last;
            if (renew_at >= valid_until)
                renew_at = valid_from + (valid_until - valid_from) * 2 / 3;
        }
    } else if (ari != "unsupported" && ari != "invalid" && ari != "unavailable" &&
               ari != "invalid_certificate_id") {
        throw std::runtime_error("Invalid renewal availability");
    }
    auto retry = metadata.at("retryAfterStatus").get<std::string>();
    if (retry != "valid" && retry != "absent" && retry != "invalid")
        throw std::runtime_error("Invalid renewal retry metadata");
    check_at = now + metadata_interval;
    if (retry == "valid") {
        auto requested = integer(metadata, "retryAt");
        if (requested > now && requested <= 253402300799LL)
            check_at = requested;
        // A zero/past hint cannot spin a cold metadata process continuously.
    }
}
json CertificateSchedule::encode() const {
    return {{"version", 1},
            {"fingerprint", fingerprint},
            {"validFrom", valid_from},
            {"validUntil", valid_until},
            {"renewAt", renew_at},
            {"checkAt", check_at},
            {"windowStart", window_start},
            {"windowEnd", window_end},
            {"issuing", issuing},
            {"uncertain", uncertain},
            {"admissionPending", admission_pending},
            {"consentBlocked", consent_blocked}};
}
CertificateSchedule CertificateSchedule::decode(const json &value) {
    only(value,
         {"version", "fingerprint", "validFrom", "validUntil", "renewAt", "checkAt", "windowStart",
          "windowEnd", "issuing", "uncertain", "admissionPending", "consentBlocked"});
    if (integer(value, "version") != 1)
        throw std::runtime_error("Unsupported certificate schedule");
    CertificateSchedule result;
    result.fingerprint = value.at("fingerprint").get<std::string>();
    result.valid_from = integer(value, "validFrom");
    result.valid_until = integer(value, "validUntil");
    result.renew_at = instant(value, "renewAt");
    result.check_at = integer(value, "checkAt");
    result.window_start = instant(value, "windowStart");
    result.window_end = instant(value, "windowEnd");
    result.issuing = value.at("issuing").get<bool>();
    result.uncertain = value.at("uncertain").get<bool>();
    result.consent_blocked = value.at("consentBlocked").get<bool>();
    result.admission_pending = value.value("admissionPending", false);
    if (result.admission_pending &&
        (!result.uncertain || result.issuing || result.fingerprint.empty()))
        throw std::runtime_error("Invalid certificate admission recovery state");
    if (!result.fingerprint.empty()) {
        if (!fingerprint_valid(result.fingerprint))
            throw std::runtime_error("Invalid scheduled certificate identity");
        dates(result.valid_from, result.valid_until);
    } else if (result.valid_from || result.valid_until || result.renew_at || result.window_start ||
               result.window_end)
        throw std::runtime_error("Absent material has a fabricated schedule");
    for (auto timestamp : {result.renew_at, static_cast<double>(result.check_at),
                           result.window_start, result.window_end})
        if (timestamp < 0 || timestamp > 253402300799LL)
            throw std::runtime_error("Invalid certificate schedule time");
    if ((result.window_start || result.window_end) && result.window_start >= result.window_end)
        throw std::runtime_error("Invalid saved renewal window");
    return result;
}

struct CertificateManager::Impl {
    CertificateSettings settings;
    std::filesystem::path state, issuer;
    std::string bundle_path, material_path, public_root_path, challenge;
    int lock = -1;
    CertificateSchedule schedule;
    TlsCertificateStatus cached;
    std::unique_ptr<OwnedOperation> operation;
    std::string operation_name, phase = "pending", reason;
    json local_metadata;
    json admitted_authority;
    int authority_watch = -1;
    bool authority_unchanged = false;
    bool local_reconciled = false;
    bool route = false, halted = false, resume_required = false, recovery_needed = false,
         awaiting_admission = false;

    Impl(const CertificateSettings &config, const std::string &data_home,
         const std::filesystem::path &executable, const std::string &broker)
        : settings(config), state(config.managed_state_directory(data_home)), issuer(executable),
          bundle_path((state / (config.mode == CertificateMode::Local ? "application.pem" : "bundle.pem")).string()),
          material_path((state / "bundle.pem").string()),
          public_root_path(config.mode == CertificateMode::Local ? (state / "local-ca.pem").string()
                                                               : config.certificate_trust_file),
          challenge(broker) {
        if ((config.mode != CertificateMode::Local &&
             (config.mode != CertificateMode::Automatic || !config.terms_agreed ||
              !std::filesystem::path(challenge).is_absolute())) || !issuer.is_absolute())
            throw std::runtime_error("Consented owned certificate operation required");
        directories(state.parent_path());
        secure_directory(state.parent_path(), true);
        bool created = mkdir(state.c_str(), 0700) == 0;
        if (!created && errno != EEXIST)
            throw std::runtime_error("Cannot create managed certificate state");
        secure_directory(state, true);
        auto identity = read_private(state / "directory.json");
        if (!identity) {
            if (!created && !std::filesystem::is_empty(state))
                throw std::runtime_error("Managed certificate CA identity missing");
            atomic_private(state / "directory.json",
                           json{{"directory", settings.store_identity()}}.dump());
        } else {
            auto saved = json::parse(*identity);
            only(saved, {"directory"});
            if (saved.at("directory") != settings.store_identity())
                throw std::runtime_error("Managed certificate CA identity mismatch");
        }
        lock =
            open((state / "manager.lock").c_str(), O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (lock < 0)
            throw std::runtime_error("Cannot own certificate manager state");
        try {
            struct stat info{};
            if (fstat(lock, &info) || !S_ISREG(info.st_mode) || info.st_uid != getuid() ||
                (info.st_mode & 0777) != 0600 || flock(lock, LOCK_EX | LOCK_NB))
                throw std::runtime_error("Certificate manager state is unsafe or already owned");
            // Retire only this manager's interrupted private writes, under its
            // exclusive lock. Go's writer temporaries and other files remain.
            for (const auto &entry : std::filesystem::directory_iterator(state)) {
                auto name = entry.path().filename().string();
                const std::string prefix = ".manager-pending-";
                if (name.rfind(prefix, 0) == 0 && name.size() == prefix.size() + 32 &&
                    name.substr(prefix.size()).find_first_not_of("0123456789abcdef") ==
                        std::string::npos) {
                    read_private(entry.path());
                    if (unlink(entry.path().c_str()))
                        throw std::runtime_error("Cannot retire interrupted certificate schedule");
                }
            }
            if (auto saved = read_private(state / "schedule.json")) {
                auto record = json::parse(*saved);
                only(record, {"directory", "domain", "termsURL", "schedule"});
                if (record.at("directory") != settings.store_identity() ||
                    record.at("domain") != settings.domain)
                    throw std::runtime_error("Certificate schedule identity mismatch");
                schedule = CertificateSchedule::decode(record.at("schedule"));
                if (record.at("termsURL") != settings.terms_url) {
                    schedule.consent_blocked = false;
                    schedule.check_at = current_time();
                }
            }
            // Local candidates, including a valid saved leaf, cannot be
            // admitted until the helper reconciles the authority and durable
            // publication. Do not write a schedule before first initialization.
            if (settings.mode == CertificateMode::Local) {
                schedule.check_at = current_time();
                return;
            }
            cached = load_application();
            if (cached.available) {
                const bool recovered = (schedule.issuing || schedule.uncertain) &&
                                       cached.fingerprint != schedule.fingerprint;
                if (recovered)
                    confirm_bundle();
                recovery_needed = schedule.issuing && cached.fingerprint == schedule.fingerprint;
                schedule.material(cached, current_time());
                if (recovered) {
                    schedule.admission_pending = true;
                    schedule.uncertain = true;
                }
                awaiting_admission = schedule.admission_pending;
                phase = awaiting_admission   ? "awaiting_admission"
                        : recovery_needed    ? "recovering"
                        : schedule.uncertain ? "failed"
                                             : "ready";
                if (schedule.uncertain && !awaiting_admission && !recovery_needed)
                    reason = "recovery_state_uncertain";
                if (recovery_needed)
                    schedule.check_at = current_time();
            } else {
                recovery_needed = schedule.issuing;
                schedule.check_at = current_time();
            }
            if (schedule.uncertain && !recovery_needed && !cached.available) {
                phase = "failed";
                reason = "recovery_state_uncertain";
            }
        } catch (...) {
            close(lock);
            lock = -1;
            throw;
        }
    }
    ~Impl() {
        stop();
        if (authority_watch >= 0)
            close(authority_watch);
        if (lock >= 0)
            close(lock);
    }
    void save() {
        atomic_private(state / "schedule.json", json{{"directory", settings.store_identity()},
                                                     {"domain", settings.domain},
                                                     {"termsURL", settings.terms_url},
                                                     {"schedule", schedule.encode()}}
                                                    .dump());
    }
    TlsCertificateStatus load_application() {
        // Material absence is a bootstrap state, while unsafe state is an
        // explicit failure. Native TLS keeps its full hostname/chain checks.
        if (!read_private(state / "bundle.pem"))
            return {};
        try {
            TlsCertificateConfig config{material_path, material_path, settings.domain,
                                        std::nullopt, std::nullopt, false};
            if (!public_root_path.empty()) {
                config.ca_file = public_root_path;
                config.ca_directory = std::string{};
            }
            TlsCertificates certificates(config, [](SSL_CTX *) {});
            return certificates.status();
        } catch (const std::exception &) {
            return {};
        }
    }
    void confirm_bundle() {
        read_private(state / "bundle.pem");
        Descriptor material(open(material_path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
        Descriptor directory(open(state.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
        if (material.fd < 0 || directory.fd < 0 || fsync(material.fd) || fsync(directory.fd))
            throw std::runtime_error("Managed certificate publication durability uncertain");
    }
    TlsCertificateStatus application() const {
        auto result = cached;
        auto now = current_time();
        result.available = result.available && now >= result.valid_from && now < result.valid_until;
        return result;
    }
    void begin(const char *name) {
        if (std::string(name) == "issue") {
            schedule.issuing = true;
            schedule.uncertain = true;
            save();
        }
        json request = {{"version", 1},
                        {"operation", name},
                        {"domain", settings.domain},
                        {"directory", settings.directory},
                        {"stateDirectory", state.string()},
                        {"challengeSocket", challenge},
                        {"termsURL", settings.terms_url},
                        {"termsAgreed", settings.terms_agreed},
                        {"apiTrustFile", settings.api_trust_file},
                        {"certificateTrustFile", settings.certificate_trust_file}};
        if (settings.mode == CertificateMode::Local)
            request = {{"version", 1}, {"operation", name}, {"domain", settings.domain},
                       {"stateDirectory", state.string()}};
        operation_name = name;
        try {
            operation = std::make_unique<OwnedOperation>(issuer, request.dump());
        } catch (const std::exception &) {
            failure("operation_start_failed", current_time());
            return;
        }
        phase = std::string(name) == "issue" ? "issuing" : "checking";
        reason.clear();
    }
    double select_window(const json &metadata) {
        if (metadata.at("ari") != "valid")
            return 0;
        auto [first, last] = renewal_window(metadata);
        if (first < 0 || first >= last || last > 253402300799LL)
            throw std::runtime_error("Invalid renewal window");
        std::uint64_t sample = 0;
        if (RAND_bytes(reinterpret_cast<unsigned char *>(&sample), sizeof(sample)) != 1)
            throw std::runtime_error("Cannot select renewal time");
        const double unit = static_cast<double>(sample >> 11) / 9007199254740992.0;
        return std::min(first + (last - first) * unit, std::nextafter(last, first));
    }
    void failure(const std::string &code, double now) {
        // Only local fixed categories reach snapshots, never the helper's raw
        // output, provider problems or input text.
        static const std::set<std::string> exposed = {"ca_terms_changed",
                                                      "consent_required",
                                                      "external_account_required",
                                                      "storage_unavailable",
                                                      "managed_material_invalid",
                                                      "managed_material_untrusted",
                                                      "certificate_trust_unavailable",
                                                      "recovery_state_uncertain",
                                                      "account_state_uncertain",
                                                      "order_state_uncertain",
                                                      "cancelled"};
        reason = exposed.count(code) ? code : "certificate_operation_failed";
        phase = "failed";
        schedule.check_at = now + metadata_interval;
        if (settings.mode == CertificateMode::Local) {
            // Preserve an already admitted generation through renewal failure.
            // Failed bootstrap must leave no new schedule that impersonates an
            // initialized authority on the next launch.
            if (local_reconciled)
                save();
            return;
        }
        if (code == "ca_terms_changed" || code == "consent_required")
            schedule.consent_blocked = true;
        if (operation_name == "issue") {
            // A child exit alone cannot prove that no bundle was published.
            auto replacement = load_application();
            if (replacement.available && replacement.fingerprint != schedule.fingerprint) {
                confirm_bundle();
                cached = replacement;
                schedule.material(cached, now);
                schedule.uncertain = true;
                schedule.admission_pending = true;
                awaiting_admission = true;
                recovery_needed = false;
                resume_required = false;
                phase = "awaiting_admission";
            } else {
                const bool unknown = code == "recovery_state_uncertain" ||
                                     code == "account_state_uncertain" ||
                                     code == "order_state_uncertain";
                schedule.issuing = unknown;
                schedule.uncertain = unknown;
                schedule.admission_pending = false;
                recovery_needed = unknown;
                resume_required = false;
            }
        }
        save();
    }
    void completed_local(const json &output, int exit_status, double now) {
        only(output, {"version", "status", "code", "reason", "publication", "local"});
        if (integer(output, "version") != 1)
            throw std::runtime_error("Invalid local issuer result version");
        const auto status = output.at("status").get<std::string>();
        if (status == "failed") {
            if (exit_status != 1 || output.contains("local") || output.contains("publication"))
                throw std::runtime_error("Invalid local issuer failure");
            failure(output.at("code").get<std::string>(), now);
            return;
        }
        if (status == "published_durability_uncertain") {
            if (exit_status != 2 || output.at("code") != "local_publication_uncertain" ||
                output.contains("local"))
                throw std::runtime_error("Invalid local uncertain result");
            const auto &publication = output.at("publication");
            only(publication, {"committed", "durable"});
            if (!publication.at("committed").get<bool>() || publication.at("durable").get<bool>())
                throw std::runtime_error("Invalid local uncertain publication");
            // The next owned ensure reconciles the committed material. Never
            // copy unconfirmed bytes into the frontend's admitted generation.
            failure("recovery_state_uncertain", now);
            return;
        }
        if (exit_status != 0 || (status != "local-issued" && status != "local-ready") ||
            operation_name != "local-ensure" || output.contains("code") || output.contains("reason"))
            throw std::runtime_error("Invalid local issuer success");
        if (status == "local-issued") {
            const auto &publication = output.at("publication");
            only(publication, {"committed", "durable"});
            if (!publication.at("committed").get<bool>() || !publication.at("durable").get<bool>())
                throw std::runtime_error("Local publication not durable");
        } else if (output.contains("publication")) {
            throw std::runtime_error("Unexpected local publication metadata");
        }
        const auto &metadata = output.at("local");
        only(metadata, {"authority", "material", "root", "leaf"});
        if (metadata.at("authority") != "current" || metadata.at("material") != "current")
            throw std::runtime_error("Local authority and material must be current");
        const auto &root = metadata.at("root"), &leaf = metadata.at("leaf");
        only(root, {"fingerprint", "validFrom", "validUntil"});
        only(leaf, {"fingerprint", "validFrom", "validUntil", "renewAt"});
        const auto root_from = integer(root, "validFrom"), root_until = integer(root, "validUntil");
        dates(root_from, root_until);
        if (now < root_from || now >= root_until ||
            !fingerprint_valid(root.at("fingerprint").get<std::string>()))
            throw std::runtime_error("Invalid local root metadata");
        auto public_pem = read_private(public_root_path);
        if (!public_pem || public_pem->size() > static_cast<size_t>(INT_MAX))
            throw std::runtime_error("Local public root unavailable");
        auto public_document = checked_local_authority(*public_pem, root, settings.domain);
        if (!local_metadata.is_null() && local_metadata.at("root") != root)
            throw std::runtime_error("Local renewal changed the admitted authority");
        // Export copies only an admitted public certificate. Watching its
        // inode keeps the owner request path free of filesystem reads and
        // invalidates a changed/replaced export without accepting new bytes.
        Descriptor watch(inotify_init1(IN_NONBLOCK | IN_CLOEXEC));
        if (watch.fd < 0 ||
            inotify_add_watch(watch.fd, public_root_path.c_str(),
                              IN_MODIFY | IN_ATTRIB | IN_MOVE_SELF | IN_DELETE_SELF |
                                  IN_CLOSE_WRITE | IN_DONT_FOLLOW) < 0)
            throw std::runtime_error("Cannot observe local public authority");
        auto confirmed_public = read_private(public_root_path);
        char event[4096];
        auto observed = read(watch.fd, event, sizeof(event));
        if (!confirmed_public || *confirmed_public != *public_pem || observed >= 0 ||
            (errno != EAGAIN && errno != EWOULDBLOCK))
            throw std::runtime_error("Local public authority changed during admission");
        auto replacement = load_application();
        const auto renew_at = integer(leaf, "renewAt");
        if (!replacement.available || leaf.at("fingerprint") != replacement.fingerprint ||
            integer(leaf, "validFrom") != replacement.valid_from ||
            integer(leaf, "validUntil") != replacement.valid_until ||
            replacement.valid_from < root_from || replacement.valid_until > root_until ||
            renew_at != std::min(replacement.valid_from + 60LL * 24 * 60 * 60,
                                 static_cast<long long>(replacement.valid_until)))
            throw std::runtime_error("Local material metadata differs from checked chain");
        confirm_bundle();
        // Keep the helper's candidate separate from the file watched by the
        // frontend. A failed/uncertain helper cannot publish a new admission.
        const auto material = read_private(material_path);
        if (!material)
            throw std::runtime_error("Checked local material missing");
        atomic_private(bundle_path, *material);
        cached = replacement;
        local_metadata = metadata;
        admitted_authority = std::move(public_document);
        if (authority_watch >= 0)
            close(authority_watch);
        authority_watch = std::exchange(watch.fd, -1);
        authority_unchanged = true;
        local_reconciled = true;
        schedule.material(cached, now);
        schedule.renew_at = renew_at;
        schedule.check_at = renew_at;
        schedule.issuing = false;
        schedule.uncertain = true;
        schedule.admission_pending = true;
        awaiting_admission = true;
        phase = "awaiting_admission";
        reason.clear();
        save();
    }
    bool authority_current() {
        if (settings.mode != CertificateMode::Local || halted || !local_reconciled ||
            !authority_unchanged || authority_watch < 0 || phase != "ready" ||
            !application().available)
            return false;
        char event[4096];
        auto count = read(authority_watch, event, sizeof(event));
        if (count < 0 && errno == EINTR)
            return false;
        if (count >= 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
            authority_unchanged = false;
            return false;
        }
        const auto now = current_time();
        const auto &root = local_metadata.at("root");
        return now >= integer(root, "validFrom") && now < integer(root, "validUntil");
    }
    void completed(const OwnedOperation::Result &result, double now) {
        auto output = json::parse(result.output);
        if (settings.mode == CertificateMode::Local) {
            completed_local(output, result.exit_status, now);
            return;
        }
        only(output, {"version", "status", "code", "reason", "caProblem", "termsURL", "publication",
                      "renewal"});
        if (integer(output, "version") != 1 || !output.at("status").is_string())
            throw std::runtime_error("Invalid issuer result schema");
        const auto status = output.at("status").get<std::string>();
        if (status == "failed") {
            if (result.exit_status != 1)
                throw std::runtime_error("Invalid failed issuer exit status");
            failure(output.at("code").get<std::string>(), now);
            return;
        }
        if (operation_name == "issue") {
            if ((status != "issued" && status != "published_durability_uncertain") ||
                (result.exit_status != 0 && result.exit_status != 2))
                throw std::runtime_error("Invalid publication result");
            only(output.at("publication"), {"committed", "durable"});
            if (!output.at("publication").at("committed").get<bool>())
                throw std::runtime_error("Certificate publication was not committed");
            auto replacement = load_application();
            if (!replacement.available)
                throw std::runtime_error("Published certificate failed local validation");
            confirm_bundle();
            cached = replacement;
            schedule.material(cached, now);
            schedule.issuing = false;
            schedule.uncertain = true;
            resume_required = false;
            schedule.admission_pending = true;
            awaiting_admission = true;
            recovery_needed = false;
            phase = "awaiting_admission";
            reason.clear();
            save();
            return;
        }
        if (status != "renewal-info" || result.exit_status != 0 || !output.contains("renewal"))
            throw std::runtime_error("Invalid renewal metadata result");
        auto metadata = output.at("renewal");
        only(metadata, {"recovery", "material", "fingerprint", "validFrom", "validUntil", "ari",
                        "windowStart", "windowEnd", "windowStartPrecise", "windowEndPrecise",
                        "retryAfterStatus", "retryAt"});
        if (recovery_needed) {
            const auto recovery = metadata.value("recovery", std::string("uncertain"));
            if (recovery == "uncertain") {
                recovery_needed = false;
                schedule.issuing = false;
                schedule.uncertain = true;
                phase = "failed";
                reason = "order_state_uncertain";
                save();
                return;
            }
            if (recovery != "none" && recovery != "completed" && recovery != "resumable")
                throw std::runtime_error("Invalid issuer recovery metadata");
            recovery_needed = false;
            resume_required = recovery == "resumable";
            if (!resume_required) {
                schedule.issuing = false;
                schedule.uncertain = false;
            }
        }
        auto material = metadata.at("material").get<std::string>();
        if (material == "absent" || material == "expired") {
            auto actual = load_application();
            if (actual.available) {
                cached = actual;
                schedule.material(cached, now);
                schedule.check_at = now;
                phase = "pending";
                save();
                return;
            }
            cached = actual;
            schedule.check_at = now;
            phase = "needs_issuance";
            reason.clear();
            save();
            return;
        }
        if (material != "current") {
            failure("managed_material_invalid", now);
            return;
        }
        auto actual = load_application();
        if (!actual.available || metadata.at("fingerprint") != actual.fingerprint) {
            cached = actual;
            schedule.check_at = now;
            phase = "pending";
            save();
            return;
        }
        cached = actual;
        schedule.material(cached, now);
        if (output.value("termsURL", std::string{}) != settings.terms_url) {
            failure("ca_terms_changed", now);
            return;
        }
        schedule.metadata(metadata, now, select_window(metadata));
        phase = "ready";
        reason.clear();
        save();
    }
    void tick() {
        if (halted)
            return;
        auto now = current_time();
        if (operation) {
            try {
                if (auto result = operation->poll()) {
                    operation.reset();
                    completed(*result, now);
                }
            } catch (const std::exception &) {
                operation.reset();
                failure(operation_name == "issue" ? "recovery_state_uncertain"
                                                  : "metadata_unavailable",
                        now);
            }
            return;
        }
        if (settings.mode == CertificateMode::Local) {
            if (!awaiting_admission && now >= schedule.check_at)
                begin("local-ensure");
            return;
        }
        if (!route) {
            phase = "validation_unavailable";
            reason = "validation_route_unavailable";
            return;
        }
        if (schedule.consent_blocked)
            return;
        if (recovery_needed) {
            if (now >= schedule.check_at)
                begin("renewal-info");
            return;
        }
        if (schedule.uncertain && !resume_required)
            return;
        if (resume_required) {
            resume_required = false;
            begin("issue");
            return;
        }
        if (phase == "needs_issuance") {
            begin("issue");
            return;
        }
        if (now >= schedule.check_at) {
            begin("renewal-info");
            return;
        }
        if (phase == "ready" && application().available && schedule.renew_at <= now)
            begin("issue");
    }
    void frontend(const TlsCertificateStatus &actual) {
        if (!actual.available)
            return;
        if (settings.mode == CertificateMode::Local &&
            (!local_reconciled || actual.fingerprint != cached.fingerprint))
            return;
        if (actual.fingerprint != cached.fingerprint) {
            auto replacement = load_application();
            if (!replacement.available || replacement.fingerprint != actual.fingerprint)
                return;
            cached = replacement;
            schedule.material(cached, current_time());
            save();
        }
        if (awaiting_admission && schedule.uncertain && actual.fingerprint == cached.fingerprint &&
            !operation) {
            confirm_bundle();
            schedule.uncertain = false;
            schedule.issuing = false;
            schedule.admission_pending = false;
            awaiting_admission = false;
            phase = "ready";
            reason.clear();
            save();
        }
    }
    void stop() {
        halted = true;
        operation.reset();
    }
};
CertificateManager::CertificateManager(const CertificateSettings &settings,
                                       const std::string &data_home,
                                       const std::filesystem::path &issuer,
                                       const std::string &broker)
    : impl(std::make_unique<Impl>(settings, data_home, issuer, broker)) {}
CertificateManager::~CertificateManager() = default;
const std::string &CertificateManager::bundle() const {
    return impl->bundle_path;
}
const std::string &CertificateManager::broker() const {
    return impl->challenge;
}
const std::string &CertificateManager::trust_file() const {
    return impl->public_root_path;
}
json CertificateManager::public_authority() const {
    if (!impl->authority_current())
        throw std::runtime_error("Local public authority is unavailable");
    return impl->admitted_authority;
}
TlsCertificateStatus CertificateManager::application() const {
    return impl->application();
}
void CertificateManager::validation_route(bool available) {
    if (impl->settings.mode == CertificateMode::Local)
        return;
    impl->route = available;
    if (available && impl->phase == "validation_unavailable") {
        impl->phase = impl->application().available ? "ready" : "pending";
        impl->schedule.check_at =
            std::min(impl->schedule.check_at, static_cast<std::int64_t>(current_time()));
    }
    if (!available && impl->operation) {
        impl->operation.reset();
        impl->failure(impl->operation_name == "issue" ? "recovery_state_uncertain"
                                                      : "metadata_unavailable",
                      current_time());
    }
}
void CertificateManager::tick() {
    impl->tick();
}
void CertificateManager::frontend(const TlsCertificateStatus &status) {
    impl->frontend(status);
}
json CertificateManager::status() const {
    auto certificate = impl->application();
    json result = {{"phase", impl->phase},
            {"reason", impl->reason},
            {"available", certificate.available},
            {"fingerprint", certificate.fingerprint},
            {"renewAt", impl->schedule.renew_at},
            {"checkAt", impl->schedule.check_at},
            {"operationActive", bool(impl->operation)},
            {"publicationUncertain", impl->schedule.uncertain}};
    if (impl->settings.mode == CertificateMode::Local) {
        result["localAuthority"] = {{"available", impl->authority_current()}};
        if (result["localAuthority"]["available"] == true) {
            result["localAuthority"].update(impl->local_metadata.at("root"));
            result["localAuthority"]["domain"] = impl->settings.domain;
        }
    }
    return result;
}
void CertificateManager::stop() {
    impl->stop();
}
} // namespace traverse
