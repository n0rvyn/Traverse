#include "endpoint_settings.hpp"
#include <functional>
#include <iostream>
#include <stdexcept>
using json = nlohmann::json;
using namespace traverse;
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
    require(rejected, "Invalid certificate configuration accepted");
}
int main() {
    try {
        json automatic = {{"schemaVersion", 1},
                          {"domain", "Desktop.Example.test."},
                          {"certificateSettings",
                           {{"mode", "automatic"},
                            {"directory", "https://ca.example.test/directory"},
                            {"termsURL", "https://ca.example.test/terms#agreement"},
                            {"termsAgreed", true}}}};
        auto endpoint = EndpointSettings::parse(automatic);
        const auto &settings = endpoint.certificates;
        require(settings.mode == CertificateMode::Automatic &&
                    settings.domain == "desktop.example.test" && settings.terms_agreed &&
                    settings.certificate.empty() && settings.private_key.empty(),
                "Automatic settings lost consent/identity");
        require(endpoint.public_url() == "https://desktop.example.test/" && endpoint.port == 443,
                "Certificate mode changed endpoint default");
        auto state = settings.managed_state_directory("/home/owner/.local/share");
        require(state.rfind("/home/owner/.local/share/traverse/certificates/", 0) == 0 &&
                    state.size() ==
                        std::string("/home/owner/.local/share/traverse/certificates/").size() + 64,
                "Managed state is not private endpoint/CA identity");
        auto repeated = EndpointSettings::parse(automatic);
        require(repeated.certificates.managed_state_directory("/home/owner/.local/share") == state,
                "Restart changes managed state identity");
        for (const auto &field : {"domain", "directory"}) {
            auto next = automatic;
            if (std::string(field) == "domain")
                next["domain"] = "other.example.test";
            else
                next["certificateSettings"]["directory"] =
                    "https://other-ca.example.test/directory";
            require(EndpointSettings::parse(next).certificates.managed_state_directory(
                        "/home/owner/.local/share") != state,
                    "Different endpoint/CA reused managed state");
        }
        auto custom = automatic;
        custom["port"] = 7443;
        custom["basePath"] = "/remote";
        require(EndpointSettings::parse(custom).certificates.managed_state_directory(
                    "/home/owner/.local/share") == state &&
                    EndpointSettings::parse(custom).public_url() ==
                        "https://desktop.example.test:7443/remote/",
                "Port/path changed certificate identity");
        for (const auto &domain : {"127.0.0.1", "::1", "[2001:db8::1]"}) {
            auto bad = automatic;
            bad["domain"] = domain;
            rejects([&] { EndpointSettings::parse(bad); });
        }
        for (const auto &field : {"certificate", "privateKey"}) {
            auto bad = automatic;
            bad[field] = "";
            rejects([&] { EndpointSettings::parse(bad); });
        }
        for (const auto &field : {"mode", "directory", "termsURL", "termsAgreed"}) {
            auto bad = automatic;
            bad["certificateSettings"].erase(field);
            rejects([&] { EndpointSettings::parse(bad); });
        }
        for (const auto &mode : {"unknown", "AUTO", ""}) {
            auto bad = automatic;
            bad["certificateSettings"]["mode"] = mode;
            rejects([&] { EndpointSettings::parse(bad); });
        }
        for (json agreement : {json(false), json(1), json("true"), json(nullptr)}) {
            auto bad = automatic;
            bad["certificateSettings"]["termsAgreed"] = agreement;
            rejects([&] { EndpointSettings::parse(bad); });
        }
        for (const auto &uri :
             {"http://ca.example.test/directory", "https://owner:credential@ca.example.test/",
              "https://ca.example.test/#fragment", "https://ca.example.test:0/",
              "https://ca.example.test:65536/", "https://ca.example.test:/",
              "https://ca.example.test/a\nb", "https:///directory"}) {
            auto bad = automatic;
            bad["certificateSettings"]["directory"] = uri;
            rejects([&] { EndpointSettings::parse(bad); });
        }
        for (const auto &uri :
             {"https://127.0.0.1:14000/directory", "https://[::1]:14000/directory",
              "https://ca.example.test/directory?profile=desktop"}) {
            auto valid = automatic;
            valid["certificateSettings"]["directory"] = uri;
            EndpointSettings::parse(valid);
        }
        for (const auto &uri :
             {"file:///terms", "http://ca.example.test/terms", "data:text/html,script",
              "data:text/plain;charset=utf-8;charset=us-ascii,terms",
              "data:text/plain;unknown,terms"}) {
            auto bad = automatic;
            bad["certificateSettings"]["termsURL"] = uri;
            rejects([&] { EndpointSettings::parse(bad); });
        }
        for (const auto &uri :
             {"", "data:text/plain,Local%20fixture", "data:;charset=UTF-8;base64,VGVybXM="}) {
            auto valid = automatic;
            valid["certificateSettings"]["termsURL"] = uri;
            EndpointSettings::parse(valid);
        }
        for (const auto &field : {"apiTrustFile", "certificateTrustFile"}) {
            auto valid = automatic;
            valid["certificateSettings"][field] = "/home/owner/trust.pem";
            EndpointSettings::parse(valid);
            for (const auto &path : {"relative.pem", "/home/owner/../trust.pem"}) {
                auto bad = automatic;
                bad["certificateSettings"][field] = path;
                rejects([&] { EndpointSettings::parse(bad); });
            }
        }
        auto unknown = automatic;
        unknown["certificateSettings"]["unknown"] = true;
        rejects([&] { EndpointSettings::parse(unknown); });
        json supplied = {{"schemaVersion", 1},
                         {"domain", "127.0.0.1"},
                         {"certificate", "certificate.pem"},
                         {"privateKey", "key.pem"}};
        auto original = EndpointSettings::parse(supplied, "", "/home/owner/config");
        require(original.certificates.mode == CertificateMode::Supplied &&
                    original.certificates.certificate == "/home/owner/config/certificate.pem",
                "Existing supplied path changed");
        supplied["certificateSettings"] = {{"mode", "supplied"}};
        require(
            EndpointSettings::parse(supplied, "", "/home/owner/config").certificates.certificate ==
                original.certificates.certificate,
            "Explicit supplied mode changes existing material");
        rejects([&] { original.certificates.managed_state_directory("/home/owner/data"); });
        for (const auto &path : {"relative", "/home/owner/../data"})
            rejects([&] { settings.managed_state_directory(path); });
        std::cout << "Certificate settings and supplied migration passed\n";
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
