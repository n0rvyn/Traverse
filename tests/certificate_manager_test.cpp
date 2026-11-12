#include "certificate_manager.hpp"
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>
using namespace traverse;
using json = nlohmann::json;
static void require(bool value, const char *message) {
    if (!value)
        throw std::runtime_error(message);
}
static void rejects(const std::function<void()> &operation) {
    bool rejected = false;
    try {
        operation();
    } catch (const std::exception &) {
        rejected = true;
    }
    require(rejected, "Invalid scheduling/state input accepted");
}
int main() {
    try {
        const std::int64_t now = 1800000000;
        TlsCertificateStatus certificate;
        certificate.available = true;
        certificate.fingerprint = std::string(64, 'a');
        certificate.valid_from = now - 300;
        certificate.valid_until = now + 600;
        CertificateSchedule schedule;
        schedule.material(certificate, now);
        require(schedule.renew_at == now + 300 && schedule.check_at == now,
                "Fallback did not use actual lifetime");
        json metadata = {{"material", "current"},
                         {"fingerprint", certificate.fingerprint},
                         {"validFrom", certificate.valid_from},
                         {"validUntil", certificate.valid_until},
                         {"ari", "valid"},
                         {"windowStart", now + 60},
                         {"windowEnd", now + 180},
                         {"retryAfterStatus", "valid"},
                         {"retryAt", now + 45}};
        schedule.metadata(metadata, now, now + 90);
        require(schedule.renew_at == now + 90 && schedule.check_at == now + 45,
                "ARI window/Retry-After lost");
        schedule.metadata(metadata, now + 10, now + 120);
        require(schedule.renew_at == now + 90, "Unchanged window selected a new target");
        auto precise = metadata;
        precise["windowStartPrecise"] = "2027-01-15T08:00:00.25Z";
        precise["windowEndPrecise"] = "2027-01-15T08:00:00.75Z";
        auto fractional = schedule;
        fractional.metadata(precise, now, now + .5);
        require(fractional.renew_at == now + .5 && fractional.window_end > fractional.window_start,
                "Subsecond ARI window was truncated");
        require(CertificateSchedule::decode(fractional.encode()).renew_at == now + .5,
                "Precise renewal selection did not survive restart");
        precise["windowStartPrecise"] = "2027-02-31T08:00:00.25Z";
        rejects([&] { fractional.metadata(precise, now, now + .5); });
        auto restored = CertificateSchedule::decode(schedule.encode());
        require(restored.encode() == schedule.encode(),
                "Restart did not preserve renewal selection");
        metadata["windowStart"] = now - 90;
        metadata["windowEnd"] = now - 30;
        restored.metadata(metadata, now, now - 60);
        require(restored.renew_at < now, "Past window was delayed");
        metadata["ari"] = "unsupported";
        metadata["retryAfterStatus"] = "invalid";
        metadata.erase("retryAt");
        restored.metadata(metadata, now, 0);
        require(restored.check_at == now + 21600, "Invalid/absent ARI retry became a busy loop");
        metadata["retryAfterStatus"] = "valid";
        metadata["retryAt"] = now;
        restored.metadata(metadata, now, 0);
        require(restored.check_at > now, "Immediate Retry-After created continuous subprocesses");
        auto changed = certificate;
        changed.fingerprint = std::string(64, 'b');
        changed.valid_until = now + 1500;
        restored.issuing = restored.uncertain = true;
        restored.material(changed, now + 1);
        require(restored.fingerprint == changed.fingerprint && !restored.issuing &&
                    !restored.uncertain && restored.window_start == 0 &&
                    restored.renew_at == now + 900,
                "New leaf retained old certificate's schedule");
        rejects([&] { restored.metadata(metadata, now, 0); });
        for (const auto &name : {"version", "fingerprint", "validUntil", "checkAt", "issuing"}) {
            auto bad = schedule.encode();
            bad.erase(name);
            rejects([&] { CertificateSchedule::decode(bad); });
        }
        for (json invalid : {json(-1), json(253402300800LL), json("123"), json(true), json(1.5),
                             json::parse("18446744073709551615")}) {
            auto bad = schedule.encode();
            bad["checkAt"] = invalid;
            rejects([&] { CertificateSchedule::decode(bad); });
        }
        auto admission = schedule.encode();
        admission["admissionPending"] = true;
        rejects([&] { CertificateSchedule::decode(admission); });
        admission["uncertain"] = true;
        require(CertificateSchedule::decode(admission).admission_pending,
                "Publication admission state lost at restart");
        auto bad = schedule.encode();
        bad["extra"] = true;
        rejects([&] { CertificateSchedule::decode(bad); });
        auto root = std::filesystem::temp_directory_path() /
                    ("traverse-manager-" + std::to_string(getpid()));
        require(mkdir(root.c_str(), 0700) == 0, "Cannot create private manager fixture");
        struct Cleanup {
            std::filesystem::path path;
            ~Cleanup() {
                std::error_code ignored;
                std::filesystem::remove_all(path, ignored);
            }
        } cleanup{root};
        CertificateSettings config;
        config.mode = CertificateMode::Automatic;
        config.domain = "desktop.example.test";
        config.directory = "https://ca.example.test/directory";
        config.terms_url = "https://ca.example.test/terms";
        config.terms_agreed = true;
        auto state = std::filesystem::path(config.managed_state_directory(root.string()));
        {
            CertificateManager manager(config, root.string(), root / "absent-issuer",
                                       (root / "broker.sock").string());
            require(!manager.application().available, "Empty state fabricated current material");
            rejects([&] { manager.public_authority(); });
            require(!manager.status().contains("localAuthority"), "Automatic state advertised local CA export");
            for (int i = 0; i < 3; ++i)
                manager.tick();
            require(manager.status().at("phase") == "validation_unavailable" &&
                        !manager.status().at("operationActive").get<bool>(),
                    "Unavailable validation started issuance");
            require(!std::filesystem::exists(state / "account-key.pem") &&
                        !std::filesystem::exists(state / "pending.json"),
                    "Manager fabricated account/order state");
            rejects([&] {
                CertificateManager duplicate(config, root.string(), root / "absent",
                                             (root / "broker.sock").string());
            });
            manager.validation_route(true);
            manager.tick();
            require(manager.status().at("phase") == "failed" &&
                        !manager.status().at("operationActive").get<bool>(),
                    "Spawn failure was hidden");
            auto check = manager.status().at("checkAt");
            manager.tick();
            require(manager.status().at("checkAt") == check,
                    "Failed spawn was retried continuously");
        }
        {
            CertificateManager reopened(config, root.string(), root / "absent",
                                        (root / "broker.sock").string());
        }
        auto outside = root / "outside";
        {
            std::ofstream output(outside);
            output << "preserve";
        }
        std::filesystem::create_symlink(outside, state / "bundle.pem");
        rejects([&] {
            CertificateManager linked(config, root.string(), root / "absent",
                                      (root / "broker.sock").string());
        });
        std::ifstream retained(outside);
        std::string content;
        retained >> content;
        require(content == "preserve", "Unsafe state inspection changed a link target");
        std::cout << "Certificate schedule, restart, absent-route safety, lock ownership and "
                     "symlink controls passed\n";
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
