// Private integration driver, never installed. Exercise the actual manager,
// issuer child and native listener through an explicit typed fixture channel.
#include "certificate_manager.hpp"
#include "common.hpp"
#include "endpoint_settings.hpp"
#include "tls_router.hpp"
#include <fcntl.h>

int main(int argc, char **argv) {
    try {
        Args args(argc, argv);
        guard_supervisor(args);
        std::signal(SIGTERM, signal_stop);
        std::signal(SIGINT, signal_stop);
        std::signal(SIGPIPE, SIG_IGN);
        std::string line;
        if (!std::getline(std::cin, line))
            throw std::runtime_error("Fixture configuration missing");
        auto input = json::parse(line);
        auto endpoint = traverse::EndpointSettings::parse(input.at("endpoint"));
        const bool local = endpoint.certificates.mode == traverse::CertificateMode::Local;
        auto data = input.at("dataHome").get<std::string>();
        auto broker = input.at("broker").get<std::string>();
        auto issuer = input.at("issuer").get<std::string>();
        auto create_manager = [&] {
            return std::make_unique<traverse::CertificateManager>(endpoint.certificates, data,
                                                                  issuer, broker);
        };
        auto manager = create_manager();
        traverse::TlsRouterConfig config;
        config.address = "127.0.0.1";
        config.port = endpoint.port;
        config.http_port = input.at("httpPort");
        config.turn_port = input.at("turnPort");
        config.certificate = config.private_key = manager->bundle();
        config.expected_host = endpoint.domain;
        config.ca_file = manager->trust_file();
        config.ca_directory = std::string{};
        if (!local)
            config.acme_socket = broker;
        config.challenge_only = !local && !manager->application().available;
        std::unique_ptr<traverse::TlsRouter> router;
        if (!local) {
            router = std::make_unique<traverse::TlsRouter>(config);
            config.port = router->port();
        }
        manager->validation_route(!local);
        auto flags = fcntl(STDIN_FILENO, F_GETFL);
        if (flags < 0 || fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK))
            throw std::runtime_error("Fixture input unavailable");
        std::string commands, previous;
        unsigned generation = 0;
        while (!stopping) {
            char bytes[1024];
            auto count = read(STDIN_FILENO, bytes, sizeof(bytes));
            if (!count)
                break;
            if (count < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
                throw std::runtime_error("Fixture control failed");
            if (count > 0)
                commands.append(bytes, count);
            auto newline = commands.find('\n');
            while (newline != std::string::npos) {
                auto command = commands.substr(0, newline);
                commands.erase(0, newline + 1);
                if (command == "stop")
                    stopping = true;
                else if (command == "export-ca") {
                    try {
                        if(!manager)throw std::runtime_error("Local manager unavailable");
                        std::cout << json{{"publicCA",manager->public_authority()}}.dump() << '\n' << std::flush;
                    } catch(const std::exception &) {
                        std::cout << json{{"publicCARejected",true}}.dump() << '\n' << std::flush;
                    }
                }
                else if (command == "pause-manager")
                    manager.reset();
                else if (command == "reload-schedule") {
                    manager.reset();
                    manager = create_manager();
                    manager->validation_route(!local);
                    ++generation;
                } else
                    throw std::runtime_error("Unknown fixture command");
                newline = commands.find('\n');
            }
            if (stopping)
                break;
            if (!manager) {
                auto status =
                    json{{"managerPaused", true}, {"managerGeneration", generation}}.dump();
                if (status != previous) {
                    std::cout << status << '\n' << std::flush;
                    previous = status;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(25));
                continue;
            }
            manager->tick();
            if (local && !router && manager->application().available) {
                router = std::make_unique<traverse::TlsRouter>(config);
                config.port = router->port();
            }
            if (config.challenge_only && manager->application().available) {
                router.reset();
                config.challenge_only = false;
                router = std::make_unique<traverse::TlsRouter>(config);
            }
            if (router) {
                router->refresh_certificate();
                manager->frontend(router->certificate_status());
            }
            auto status = manager->status();
            status["managerGeneration"] = generation;
            status["managerPaused"] = false;
            status["proofOnly"] = config.challenge_only;
            status["port"] = router ? router->port() : config.port;
            status["frontendFingerprint"] = router ? router->certificate_status().fingerprint : "";
            status["frontendRevision"] = router ? router->certificate_status().revision : 0;
            auto encoded = status.dump();
            if (encoded != previous) {
                std::cout << encoded << '\n' << std::flush;
                previous = std::move(encoded);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(25));
        }
        if (manager)
            manager->stop();
        if (router)
            router->stop();
        std::cout << json{{"stopped", true}}.dump() << '\n' << std::flush;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
