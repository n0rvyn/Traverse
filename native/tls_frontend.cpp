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

static std::atomic<bool> stopped{false};
static void stop(int) {
    stopped = true;
}
int main(int argc, char **argv) {
    try {
        std::map<std::string, std::string> args;
        for (int i = 1; i < argc; i += 2) {
            if (i + 1 == argc)
                throw std::runtime_error("Expected option value");
            std::string key = argv[i];
            if (key != "--host" && key != "--port" && key != "--http-port" &&
                key != "--turn-port" && key != "--cert" && key != "--key" &&
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
        traverse::TlsRouter router(config);
        std::cout << "{\"port\":" << router.port() << "}" << std::endl;
        while (!stopped)
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        router.stop();
    } catch (const std::exception &error) {
        std::cerr << "TLS front end: " << error.what() << '\n';
        return 1;
    }
}
