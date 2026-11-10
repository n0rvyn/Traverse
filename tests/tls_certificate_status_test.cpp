#include "tls_certificate.hpp"
#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>

using nlohmann::json;
using namespace traverse;
static void require(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
template <typename F> static void rejects(F fn) {
    bool failed = false;
    try { fn(); } catch (const std::exception &) { failed = true; }
    require(failed, "Invalid certificate state accepted");
}
int main() {
    try {
        char pattern[] = "/tmp/traverse-cert-state-XXXXXX";
        auto *created = mkdtemp(pattern); require(created, "Cannot create status fixture");
        std::filesystem::path root(created), path = root / "status.json";
        struct Cleanup { std::filesystem::path path; ~Cleanup() { std::filesystem::remove_all(path); } } cleanup{root};
        TlsCertificateStatus absent{0, "", "Certificate not yet provisioned", 0, 0, false};
        write_tls_certificate_status(path, absent);
        rejects([&] { read_tls_certificate_status(path, getpid()); });
        auto read = read_tls_certificate_status(path, getpid(), true);
        require(!read.available && read.revision == 0 && read.fingerprint.empty() &&
                    read.valid_from == 0 && read.valid_until == 0 && read.error == absent.error,
                "Absent certificate state did not roundtrip");
        json snapshot; { std::ifstream input(path); input >> snapshot; }
        auto publish = [&](const json &value) { std::ofstream file(path); file << value.dump(); };
        for (const auto &key : {"available", "revision", "fingerprint", "validFrom", "validUntil"}) {
            auto value = snapshot;
            if (std::string(key) == "available") value[key] = true;
            else if (std::string(key) == "fingerprint") value[key] = std::string(64, 'a');
            else value[key] = 1;
            publish(value); rejects([&] { read_tls_certificate_status(path, getpid(), true); });
        }
        publish(snapshot);
        rejects([&] { read_tls_certificate_status(path, getpid() + 1, true); });
        auto stale = snapshot;
        auto observed = stale.at("observedMonotonicMs").get<std::int64_t>();
        stale["observedMonotonicMs"] = observed > 16000 ? observed - 16000 : -1;
        publish(stale); rejects([&] { read_tls_certificate_status(path, getpid(), true); });
        publish(snapshot); chmod(path.c_str(), 0644);
        rejects([&] { read_tls_certificate_status(path, getpid(), true); });
        chmod(path.c_str(), 0600);
        auto link = root / "link.json"; std::filesystem::create_symlink(path, link);
        rejects([&] { read_tls_certificate_status(link, getpid(), true); });
        rejects([&] { write_tls_certificate_status(link, absent); });
        auto now = std::time(nullptr); require(now != static_cast<std::time_t>(-1), "Fixture clock failed");
        TlsCertificateStatus loaded{1, std::string(64, 'a'), "", now - 60, now + 60, true};
        write_tls_certificate_status(path, loaded);
        for (bool allow : {false, true}) {
            auto valid = read_tls_certificate_status(path, getpid(), allow);
            require(valid.available && valid.revision == 1 && valid.fingerprint == loaded.fingerprint,
                    "Loaded state promotion did not reach both readers");
        }
        std::cout << "Absent/loaded status, strict opt-in, inconsistent tuple and owner/freshness controls passed\n";
    } catch (const std::exception &error) { std::cerr << error.what() << '\n'; return 1; }
}
