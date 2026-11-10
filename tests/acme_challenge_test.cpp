#include "acme_challenge.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <nlohmann/json.hpp>
#include <openssl/x509v3.h>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

using nlohmann::json;
using traverse::AcmeChallenges;
static void require(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
static void rejects(const std::function<void()> &fn) {
    bool caught = false;
    try { fn(); } catch (const std::exception &) { caught = true; }
    require(caught, "Unsafe challenge configuration accepted");
}
struct Descriptor {
    int fd;
    explicit Descriptor(int value) : fd(value) {}
    ~Descriptor() { if (fd >= 0) close(fd); }
    void reset() { if (fd >= 0) close(fd); fd = -1; }
};
static void eventually(const std::function<bool()> &ready) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(4);
    while (!ready()) {
        require(std::chrono::steady_clock::now() < deadline, "Challenge transition timeout");
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}
static int connect_owner(const std::string &path) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    require(fd >= 0, "Owner socket failed");
    timeval timeout{3, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    sockaddr_un address{}; address.sun_family = AF_UNIX;
    require(path.size() < sizeof(address.sun_path), "Fixture socket path too long");
    std::memcpy(address.sun_path, path.c_str(), path.size() + 1);
    if (connect(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address))) {
        close(fd); throw std::runtime_error("Owner could not connect");
    }
    return fd;
}
static void transfer(int fd, void *bytes, size_t length, bool output) {
    auto *cursor = static_cast<unsigned char *>(bytes);
    while (length) {
        auto count = output ? send(fd, cursor, length, MSG_NOSIGNAL) : recv(fd, cursor, length, 0);
        if (count < 0 && errno == EINTR) continue;
        require(count > 0, "Fixture transfer failed");
        cursor += count; length -= static_cast<size_t>(count);
    }
}
static bool response(int fd) {
    std::uint32_t size = 0; transfer(fd, &size, sizeof(size), false); size = ntohl(size);
    require(size > 0 && size < 64, "Unexpected challenge acknowledgement");
    std::string result(size, '\0'); transfer(fd, result.data(), result.size(), false);
    auto parsed = json::parse(result);
    require(parsed.size() == 1 && parsed.at("ready").is_boolean(), "Unexpected acknowledgement schema");
    return parsed.at("ready").get<bool>();
}
static bool request(int fd, std::string message) {
    auto size = htonl(static_cast<std::uint32_t>(message.size()));
    transfer(fd, &size, sizeof(size), true); transfer(fd, message.data(), message.size(), true);
    return response(fd);
}
static void certificate(const std::shared_ptr<const traverse::AcmeChallengeContext> &context,
                        const std::array<unsigned char, 32> &digest) {
    auto *cert = SSL_CTX_get0_certificate(context->ssl.get());
    require(cert && X509_get_version(cert) == 2, "Missing challenge certificate");
    auto *key = X509_get0_pubkey(cert);
    require(key && X509_verify(cert, key) == 1 && EVP_PKEY_get_bits(key) == 256,
            "Challenge signature/public key invalid");
    std::tm expiry{};
    require(ASN1_TIME_to_tm(X509_get0_notAfter(cert), &expiry) == 1 &&
                static_cast<std::int64_t>(timegm(&expiry)) == context->expires,
            "Challenge certificate expiry units changed");
    char group[80]{}; size_t length = 0;
    require(EVP_PKEY_get_utf8_string_param(key, "group", group, sizeof(group), &length) == 1 &&
                std::string(group) == "prime256v1", "Challenge key is not P256");
    std::unique_ptr<GENERAL_NAMES, decltype(&GENERAL_NAMES_free)> names(
        static_cast<GENERAL_NAMES *>(X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr)),
        GENERAL_NAMES_free);
    require(names && sk_GENERAL_NAME_num(names.get()) == 1, "Challenge must have one SAN");
    auto *dns = sk_GENERAL_NAME_value(names.get(), 0);
    require(dns->type == GEN_DNS && ASN1_STRING_length(dns->d.dNSName) == 12 &&
                !std::memcmp(ASN1_STRING_get0_data(dns->d.dNSName), "example.test", 12),
            "Challenge DNS SAN invalid");
    std::unique_ptr<ASN1_OBJECT, decltype(&ASN1_OBJECT_free)> oid(
        OBJ_txt2obj("1.3.6.1.5.5.7.1.31", 1), ASN1_OBJECT_free);
    auto index = X509_get_ext_by_OBJ(cert, oid.get(), -1);
    require(index >= 0 && X509_get_ext_by_OBJ(cert, oid.get(), index) == -1,
            "Challenge extension missing/duplicated");
    auto *extension = X509_get_ext(cert, index);
    require(X509_EXTENSION_get_critical(extension) == 1, "Challenge extension must be critical");
    auto *value = X509_EXTENSION_get_data(extension);
    auto *encoded = ASN1_STRING_get0_data(value);
    require(ASN1_STRING_length(value) == 34 && encoded[0] == 4 && encoded[1] == 32 &&
                !std::memcmp(encoded + 2, digest.data(), digest.size()),
            "Challenge extension DER/digest invalid");
    auto *cursor = encoded;
    std::unique_ptr<ASN1_OCTET_STRING, decltype(&ASN1_OCTET_STRING_free)> decoded(
        d2i_ASN1_OCTET_STRING(nullptr, &cursor, ASN1_STRING_length(value)), ASN1_OCTET_STRING_free);
    require(decoded && ASN1_STRING_length(decoded.get()) == 32 && cursor == encoded + 34,
            "Independent DER decoding failed");
    require(SSL_CTX_get_session_cache_mode(context->ssl.get()) == SSL_SESS_CACHE_OFF &&
                SSL_CTX_get_num_tickets(context->ssl.get()) == 0 &&
                SSL_CTX_get_max_early_data(context->ssl.get()) == 0,
            "Challenge session reuse policy invalid");
}

int main() {
    try {
        char pattern[] = "/tmp/traverse-acme-XXXXXX";
        auto *created = mkdtemp(pattern); require(created, "Cannot create fixture directory");
        std::filesystem::path root(created);
        struct Cleanup { std::filesystem::path path; ~Cleanup() { std::filesystem::remove_all(path); } } cleanup{root};
        auto path = (root / "control.sock").string();
        std::array<unsigned char, 32> digest{};
        for (size_t i = 0; i < digest.size(); ++i) digest[i] = static_cast<unsigned char>(i);
        unsigned char base64[45]{}; require(EVP_EncodeBlock(base64, digest.data(), digest.size()) == 44, "Fixture digest failed");
        std::string encoded(reinterpret_cast<char *>(base64), 43);
        std::replace(encoded.begin(), encoded.end(), '+', '-'); std::replace(encoded.begin(), encoded.end(), '/', '_');
        json valid = {{"version", 1}, {"domain", "example.test"}, {"sha256", encoded}, {"expires", std::time(nullptr) + 60}};
        for (const auto &domain : {"*.example.test", "127.0.0.1", "::1", "bad..test"})
            rejects([&] { AcmeChallenges server(path, domain); });
        chmod(root.c_str(), 0755);
        rejects([&] { AcmeChallenges server(path, "example.test"); });
        chmod(root.c_str(), 0700);
        std::filesystem::create_directory_symlink(root, root / "link");
        rejects([&] { AcmeChallenges server((root / "link/socket").string(), "example.test"); });
        std::filesystem::remove(root / "link");
        { std::ofstream existing(path); existing << "retain-owned-marker"; }
        rejects([&] { AcmeChallenges server(path, "example.test"); });
        require(std::filesystem::file_size(path) == 19, "Existing owner data modified");
        std::filesystem::remove(path);
        auto marker = root / "marker"; { std::ofstream output(marker); output << "retain-owned-marker"; }
        std::filesystem::create_symlink(marker, path);
        rejects([&] { AcmeChallenges server(path, "example.test"); });
        require(std::filesystem::is_symlink(path) && std::filesystem::file_size(marker) == 19,
                "Existing symlink/target modified");
        std::filesystem::remove(path);
        AcmeChallenges server(path, "EXAMPLE.test.");
        require(server.domain() == "example.test" && !server.current(), "Initial owner/domain state invalid");
        struct stat mode{}; require(!lstat(path.c_str(), &mode) && (mode.st_mode & 0777) == 0600,
                                    "Challenge socket not owner-only");
        for (const auto &field : {"version", "domain", "sha256", "expires"}) {
            auto bad = valid; bad.erase(field);
            Descriptor client(connect_owner(path)); require(!request(client.fd, bad.dump()), "Missing field accepted");
        }
        for (json bad : {json("1"), json(true), json(0), json(2)}) {
            auto value = valid; value["version"] = bad;
            Descriptor client(connect_owner(path)); require(!request(client.fd, value.dump()), "Invalid version accepted");
        }
        for (const auto &domain : {"other.test", "*.example.test", "127.0.0.1", "example.test/path"}) {
            auto value = valid; value["domain"] = domain;
            Descriptor client(connect_owner(path)); require(!request(client.fd, value.dump()), "Wrong domain accepted");
        }
        for (const auto &text : {std::string(""), std::string(43, '!'), encoded.substr(0, 42), encoded.substr(0, 42) + 'B'}) {
            auto value = valid; value["sha256"] = text;
            Descriptor client(connect_owner(path)); require(!request(client.fd, value.dump()), "Invalid digest accepted");
        }
        for (json expiry : {json(0), json(-1), json(true), json("tomorrow"), json(1.5),
                            json::parse("9223372036854775807"), json::parse("18446744073709551615")}) {
            auto value = valid; value["expires"] = expiry;
            Descriptor client(connect_owner(path)); require(!request(client.fd, value.dump()), "Invalid expiry accepted");
        }
        { auto value = valid; value["extra"] = "private-marker";
          Descriptor client(connect_owner(path)); require(!request(client.fd, value.dump()), "Unknown field accepted"); }
        { Descriptor client(connect_owner(path)); require(!request(client.fd, valid.dump(2)), "Noncompact frame accepted"); }
        { auto duplicate = valid.dump(); duplicate.insert(1, "\"domain\":\"example.test\",");
          Descriptor client(connect_owner(path)); require(!request(client.fd, duplicate), "Duplicate field accepted"); }
        { Descriptor client(connect_owner(path)); auto size = htonl(0xffffffffU);
          transfer(client.fd, &size, sizeof(size), true); require(!response(client.fd), "Oversize frame accepted"); }
        { Descriptor client(connect_owner(path)); auto size = htonl(20U);
          transfer(client.fd, &size, sizeof(size), true); char partial = '{'; transfer(client.fd, &partial, 1, true); }
        Descriptor lease(connect_owner(path)); require(request(lease.fd, valid.dump()), "Valid owner lease denied");
        auto context = server.current(); require(context && context->valid_now(), "Valid lease not published");
        certificate(context, digest);
        { Descriptor competitor(connect_owner(path)); require(!request(competitor.fd, valid.dump()), "Concurrent issuer replaced live lease"); }
        require(server.current() == context, "Rejected issuer modified active context");
        lease.reset(); eventually([&] { return !server.current(); });
        require(!context->valid_now(), "Closed lease remains valid");
        auto short_lived = valid; short_lived["expires"] = std::time(nullptr) + 2;
        Descriptor old(connect_owner(path)); require(request(old.fd, short_lived.dump()), "Expiry fixture denied");
        auto expired = server.current(); eventually([&] { return !server.current(); });
        Descriptor replacement(connect_owner(path)); require(request(replacement.fd, valid.dump()), "Replacement lease denied");
        auto renewed = server.current(); old.reset();
        eventually([&] { return !expired->active.load(); });
        require(server.current() == renewed && renewed->valid_now(), "Old lease cleanup revoked replacement");
        char unexpected = 'x'; transfer(replacement.fd, &unexpected, 1, true);
        eventually([&] { return !server.current(); }); replacement.reset();
        if (geteuid() == 0) {
            // Only this temporary fixture becomes reachable to the foreign UID.
            // The child's post-fork path uses syscalls only, never copied C++ locks.
            chmod(root.c_str(), 0711); chmod(path.c_str(), 0666);
            sockaddr_un address{}; address.sun_family = AF_UNIX;
            std::memcpy(address.sun_path, path.c_str(), path.size() + 1);
            auto child = fork(); require(child >= 0, "Cannot fork credential fixture");
            if (child == 0) {
                if (setgid(65534) || setuid(65534)) _exit(2);
                int fd = socket(AF_UNIX, SOCK_STREAM, 0); if (fd < 0) _exit(3);
                timeval deadline{2, 0}; setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &deadline, sizeof(deadline));
                if (connect(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address))) _exit(4);
                char byte; auto result = recv(fd, &byte, 1, 0); close(fd); _exit(result == 0 ? 0 : 5);
            }
            int status = 0; require(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
                                    "Foreign UID was not rejected by peer credentials");
            chmod(path.c_str(), 0600); chmod(root.c_str(), 0700);
        } else std::cout << "Foreign-UID fixture requires root; owner/path tests still run\n";
        Descriptor pending(connect_owner(path));
        Descriptor final_lease(connect_owner(path)); require(request(final_lease.fd, valid.dump()), "Final lease denied");
        auto final_context = server.current(); server.stop();
        require(!server.current() && !final_context->valid_now() && !std::filesystem::exists(path),
                "Stop did not revoke/release owner resources");
        { auto replaced = (root / "replaced.sock").string();
          AcmeChallenges owner(replaced, "example.test"); std::filesystem::remove(replaced);
          { std::ofstream file(replaced); file << "preserve-replacement"; }
          owner.stop(); require(std::filesystem::file_size(replaced) == 20, "Cleanup deleted replacement path"); }
        { std::string domain = std::string(63, 'a') + "." + std::string(63, 'b') + "." +
                               std::string(63, 'c') + "." + std::string(61, 'd');
          auto long_path = (root / "long.sock").string(); AcmeChallenges owner(long_path, domain);
          auto value = valid; value["domain"] = domain;
          Descriptor client(connect_owner(long_path)); require(request(client.fd, value.dump()), "RFC-length DNS challenge denied");
          auto challenge = owner.current(); auto *cert = SSL_CTX_get0_certificate(challenge->ssl.get());
          std::unique_ptr<GENERAL_NAMES, decltype(&GENERAL_NAMES_free)> names(
              static_cast<GENERAL_NAMES *>(X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr)), GENERAL_NAMES_free);
          require(names && sk_GENERAL_NAME_num(names.get()) == 1 &&
                      ASN1_STRING_length(sk_GENERAL_NAME_value(names.get(), 0)->d.dNSName) == 253,
                  "Long DNS SAN was truncated"); }
        std::cout << "Owned lease, RFC8737 certificate, invalid input, expiry, credentials and cleanup passed\n";
    } catch (const std::exception &error) { std::cerr << error.what() << '\n'; return 1; }
}
