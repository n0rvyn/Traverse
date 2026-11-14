#include "endpoint_settings.hpp"
#include <functional>
#include <iostream>
#include <stdexcept>
using json = nlohmann::json;
using traverse::EndpointMode;
using traverse::EndpointSettings;
static void require(bool condition, const char *message) {
    if (!condition)
        throw std::runtime_error(message);
}
static void rejects(const std::function<void()> &operation) {
    bool rejected = false;
    try {
        operation();
    } catch (const std::exception &) {
        rejected = true;
    }
    require(rejected, "Invalid configuration was accepted");
}
int main() {
    try {
        json config = {{"schemaVersion", 1},
                       {"domain", "Desktop.Example.COM"},
                       {"certificate", "/tmp/test.crt"},
                       {"privateKey", "/tmp/test.key"}};
        require(EndpointSettings::normalize_host("EXAMPLE.com.") == "example.com" &&
                    EndpointSettings::normalize_host("xn--bcher-kva.example") == "xn--bcher-kva.example" &&
                    EndpointSettings::normalize_host("[2001:0db8::1]") == "2001:db8::1" &&
                    EndpointSettings::normalize_host("127.0.0.1") == "127.0.0.1",
                "Shared host normalization changed");
        for (const auto &host : {"", "*.example.com", "bad..example", "https://example.com",
                                 "example.com/path", "127.1", "example.123", "-bad.example"})
            rejects([&] { EndpointSettings::normalize_host(host); });
        auto settings = EndpointSettings::parse(config, ":99");
        require(settings.mode == EndpointMode::Standalone && settings.port == 443 &&
                    settings.media_port == 443 && settings.frontend_port() == 443 &&
                    settings.turn_backend_port == 0,
                "New default is not one port443");
        require(settings.origin == "https://desktop.example.com" &&
                    settings.public_url() == "https://desktop.example.com/",
                "Default URL is not canonical");
        require(settings.turns_url() == "turns:desktop.example.com:443?transport=tcp" &&
                    settings.display == ":99",
                "Derived TURN/display mismatch");
        require(!settings.observer,"Observer silently enabled for existing config");
        auto observer_config=config;
        observer_config["observerSettings"]={{"host","Observer.Example.test"},{"port",9443},{"caFile",""},
            {"registrationId",std::string(32,'a')},{"tokenFile","/private/token"},{"timeoutMs",nullptr}};
        auto with_observer=EndpointSettings::parse(observer_config);
        require(with_observer.observer && with_observer.observer->host=="observer.example.test" && with_observer.port==443,
            "Optional observer changed endpoint defaults");
        auto custom = config;
        custom["port"] = 7443;
        custom["basePath"] = "/traverse/v1.2";
        auto prefixed = EndpointSettings::parse(custom);
        require(prefixed.public_url() == "https://desktop.example.com:7443/traverse/v1.2/" &&
                    prefixed.media_port == 7443,
                "Custom URL/media port diverged");
        auto proxied = config;
        proxied["listenAddress"] = "127.0.0.1";
        proxied["listenPort"] = 18443;
        proxied["turnBackendPort"] = 18444;
        proxied["basePath"] = "/remote/";
        auto backend = EndpointSettings::parse(proxied);
        require(backend.frontend_port() == 18443 && backend.turn_backend_port == 18444,
                "Explicit loopback bindings were not retained");
        require(backend.public_url() == "https://desktop.example.com/remote/" &&
                    backend.turns_url() == "turns:desktop.example.com:443?transport=tcp" &&
                    backend.media_port == 443,
                "Private bindings changed public URLs or media port");
        require(!backend.proxy_tls, "Private ports alone must not imply proxy TLS");
        proxied["proxyTls"] = true;
        require(EndpointSettings::parse(proxied).proxy_tls, "Explicit proxy TLS metadata lost");
        for (json bad : {json(1), json("true"), json(nullptr)}) {
            auto invalid = proxied;
            invalid["proxyTls"] = bad;
            rejects([&] { EndpointSettings::parse(invalid); });
        }
        auto loopback6 = proxied;
        loopback6["listenAddress"] = "::1";
        require(EndpointSettings::parse(loopback6).frontend_port() == 18443,
                "IPv6 loopback backend was rejected");
        for (const auto &address : {"0.0.0.0", "192.0.2.1", "::", "2001:db8::1"}) {
            auto exposed = proxied;
            exposed["listenAddress"] = address;
            rejects([&] { EndpointSettings::parse(exposed); });
        }
        auto collision = proxied;
        collision["turnBackendPort"] = 18443;
        rejects([&] { EndpointSettings::parse(collision); });
        for (const auto &field : {"listenPort", "turnBackendPort"}) {
            for (json bad : {json(0), json(-1), json(65536), json(true), json("18443"),
                             json(18443.0), json::parse("18446744073709552616")}) {
                auto invalid = proxied;
                invalid[field] = bad;
                rejects([&] { EndpointSettings::parse(invalid); });
            }
        }
        auto relative = config;
        relative["certificate"] = "cert with spaces.pem";
        relative["privateKey"] = "key.pem";
        rejects([&] { EndpointSettings::parse(relative); });
        auto resolved = EndpointSettings::parse(relative, "", "/home/owner/.config/traverse");
        require(resolved.certificates.certificate == "/home/owner/.config/traverse/cert with spaces.pem" &&
                    resolved.certificates.private_key == "/home/owner/.config/traverse/key.pem",
                "Relative TLS paths did not use their configuration directory");
        for (const auto &[host, expected] : std::vector<std::pair<std::string, std::string>>{
                 {"2001:0db8::1", "https://[2001:db8::1]"},
                 {"[::1]", "https://[::1]"},
                 {"127.0.0.1", "https://127.0.0.1"},
                 {"localhost", "https://localhost"},
                 {"EXAMPLE.com.", "https://example.com"}}) {
            auto value = config;
            value["domain"] = host;
            require(EndpointSettings::parse(value).origin == expected, "Host serialization failed");
        }
        for (json bad : {json(0), json(-1), json(65536), json(true), json("443"), json(443.0),
                         json(22), json(6000), json::parse("18446744073709552616")}) {
            auto value = config;
            value["port"] = bad;
            rejects([&] { EndpointSettings::parse(value); });
        }
        for (const auto &host : {"",
                                 "https://example.com",
                                 "example.com:443",
                                 "x@y",
                                 "a/b",
                                 "a?b",
                                 "a#b",
                                 "a..b",
                                 "a..",
                                 "-bad.example",
                                 "bad-.example",
                                 "127.1",
                                 "999.1.1.1",
                                 "[:::]",
                                 "[]",
                                 "[127.0.0.1]",
                                 "0x7f000001",
                                 "0x7f.1",
                                 "host.123",
                                 "a\nb",
                                 "a%2eb"}) {
            auto value = config;
            value["domain"] = host;
            rejects([&] { EndpointSettings::parse(value); });
        }
        for (const auto &path : {"", "relative", "//", "/a//b", "/../", "/./", "/a/../../",
                                 "/%2e%2e/", "/a?b", "/a#b", "/a\\b", "/a\nb"})
            rejects([&] { EndpointSettings::normalize_base_path(path); });
        for (json bad : {json(true), json(0), json(2), json("1"), json(1.0)}) {
            auto value = config;
            value["schemaVersion"] = bad;
            rejects([&] { EndpointSettings::parse(value); });
        }
        for (const auto &field : {"origin", "httpsPort", "mediaPort", "unrecognized"}) {
            auto value = config;
            value[field] = 443;
            rejects([&] { EndpointSettings::parse(value); });
        }
        auto legacy = json{{"origin", "https://example.com:8443"},
                           {"certificate", "test.crt"},
                           {"privateKey", "test.key"}};
        auto old = EndpointSettings::parse(legacy);
        rejects([&] { old.turns_url(); });
        require(old.mode == EndpointMode::Legacy && old.port == 8443 && old.media_port == 50000 &&
                    old.public_url() == "https://example.com:8443",
                "Legacy omitted ports changed");
        require(EndpointSettings::parse(legacy, "", "/tmp/config").certificates.certificate == "test.crt",
                "Legacy relative TLS paths changed");
        legacy["httpsPort"] = 9443;
        legacy["origin"] = "https://example.com:9443";
        legacy["mediaPort"] = 55000;
        old = EndpointSettings::parse(legacy);
        require(old.port == 9443 && old.media_port == 55000, "Legacy explicit ports changed");
        legacy["mediaPort"] = 9443;
        rejects([&] { EndpointSettings::parse(legacy); });
        rejects([&] { EndpointSettings::parse(json::array()); });
        std::cout << "Endpoint defaults, custom URLs, legacy compatibility and hostile input "
                     "checks passed\n";
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
