#include "tls_router.hpp"
#include <atomic>
#include <chrono>
#include <csignal>
#include <iostream>
#include <limits>
#include <map>
#include <stdexcept>
#include <sys/prctl.h>
#include <thread>
#include <unistd.h>

static volatile std::sig_atomic_t stopped = 0, refresh_requested = 0;
static void stop(int) {
    stopped = 1;
}
static void refresh(int) { refresh_requested = 1; }
int main(int argc, char **argv) {
    try {
        std::map<std::string, std::string> args;
        for (int i = 1; i < argc; i += 2) {
            if (i + 1 == argc)
                throw std::runtime_error("Expected option value");
            std::string key = argv[i];
            if (key != "--host" && key != "--port" && key != "--http-port" &&
                key != "--turn-port" && key != "--cert" && key != "--key" &&
                key != "--expected-domain" && key != "--trust-file" && key != "--trust-directory" &&
                key != "--status-file" &&
                key != "--acme-socket" && key != "--certificate-bootstrap" &&
                key != "--supervisor-pid")
                throw std::runtime_error("Unknown option");
            if (!args.emplace(key, argv[i + 1]).second)
                throw std::runtime_error("Duplicate option");
        }
        auto port = [&](const char *key) {
            const auto &text = args.at(key);
            if (text.empty() || text.find_first_not_of("0123456789") != std::string::npos)
                throw std::runtime_error("Invalid port");
            auto value = std::stoul(text);
            if (value > 65535)
                throw std::runtime_error("Invalid port");
            return static_cast<unsigned short>(value);
        };
        std::signal(SIGTERM, stop);
        std::signal(SIGINT, stop);
        std::signal(SIGHUP, refresh);
        std::signal(SIGPIPE, SIG_IGN);
        if (args.count("--supervisor-pid")) {
            const auto &text = args.at("--supervisor-pid");
            if (text.empty() || text.find_first_not_of("0123456789") != std::string::npos)
                throw std::runtime_error("Invalid supervisor PID");
            auto value = std::stoul(text);
            if (!value || value > static_cast<unsigned>(std::numeric_limits<pid_t>::max()))
                throw std::runtime_error("Invalid supervisor PID");
            if (prctl(PR_SET_PDEATHSIG, SIGTERM) || getppid() != static_cast<pid_t>(value))
                throw std::runtime_error("Supervisor unavailable");
        }
        traverse::TlsRouterConfig config;
        config.address = args.at("--host");
        config.port = port("--port");
        config.http_port = port("--http-port");
        config.turn_port = port("--turn-port");
        config.certificate = args.at("--cert");
        config.private_key = args.at("--key");
        if (args.count("--expected-domain")) config.expected_host = args.at("--expected-domain");
        if (args.count("--trust-file")) config.ca_file = args.at("--trust-file");
        if (args.count("--trust-directory")) config.ca_directory = args.at("--trust-directory");
        if (args.count("--acme-socket")) {
            config.acme_socket = args.at("--acme-socket");
            if (config.acme_socket.empty()) throw std::runtime_error("Certificate challenge socket required");
        }
        if (args.count("--certificate-bootstrap")) {
            const auto &value = args.at("--certificate-bootstrap");
            if (value != "true" && value != "false") throw std::runtime_error("Invalid certificate bootstrap mode");
            config.allow_certificate_bootstrap = value == "true";
        }
        traverse::TlsRouter router(config);
        auto status_file = args.count("--status-file") ? args.at("--status-file") : std::string{};
        if (args.count("--status-file") && status_file.empty())
            throw std::runtime_error("Certificate status path required");
        if (!status_file.empty())
            traverse::write_tls_certificate_status(status_file, router.certificate_status());
        std::cout << "{\"port\":" << router.port() << "}" << std::endl;
        std::string previous_error;
        std::string publication_error;
        auto next_publication = std::chrono::steady_clock::now() + std::chrono::seconds(1);
        auto published = router.certificate_status();
        while (!stopped) {
            bool forced = false;
            if (refresh_requested) {
                refresh_requested = 0;
                forced = true;
            }
            router.refresh_certificate(forced);
            auto status = router.certificate_status();
            auto error = status.available ? status.error :
                status.revision ? "Active certificate is expired or not yet valid" : "Certificate not yet provisioned";
            if (error != previous_error) {
                if (!error.empty()) std::cerr << "TLS certificate reload: " << error << '\n';
                previous_error = error;
            }
            auto now = std::chrono::steady_clock::now();
            if (!status_file.empty() && (forced || now >= next_publication ||
                status.revision != published.revision || status.error != published.error ||
                status.available != published.available)) {
                next_publication = now + std::chrono::seconds(1);
                try {
                    traverse::write_tls_certificate_status(status_file, status);
                    published = status;
                    publication_error.clear();
                } catch (const std::exception &failure) {
                    if (publication_error != failure.what())
                        std::cerr << "TLS certificate status publication: " << failure.what() << '\n';
                    publication_error = failure.what();
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        router.stop();
    } catch (const std::exception &error) {
        std::cerr << "TLS front end: " << error.what() << '\n';
        return 1;
    }
}
