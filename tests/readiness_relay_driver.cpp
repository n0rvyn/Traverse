// Test-only TLS bridge driver. Config and cancellation use a private pipe;
// the connected local TURN socket is inherited. Nothing is installed.
#include "readiness_relay.hpp"
#include <atomic>
#include <csignal>
#include <iostream>
#include <nlohmann/json.hpp>
#include <poll.h>
#include <thread>
#include <unistd.h>
int main() {
    std::signal(SIGPIPE, SIG_IGN);
    try {
        std::string line;std::getline(std::cin,line);
        auto c=nlohmann::json::parse(line);
        traverse::ProbeTlsEndpoint e{c.at("address"),c.at("hostname"),c.at("ca"),c.at("alpn"),c.at("port").get<std::uint16_t>()};
        std::atomic<bool> stopped{false},done{false};
        nlohmann::json result;
        std::thread worker([&]{
            try {
                const bool closed=traverse::forward_probe_tls(e,c.at("fd"),stopped);
                result={{"status",closed?"closed":"cancelled"}};
            }
            catch(const std::exception &error){result={{"status","rejected"},{"error",error.what()}};}
            done=true;
        });
        while(!done) {
            pollfd event{STDIN_FILENO,POLLIN,0};
            if(poll(&event,1,100)>0){char byte;auto received=read(STDIN_FILENO,&byte,1);if(received>=0){stopped=true;break;}}
        }
        worker.join();std::cout<<result.dump()<<'\n';return 0;
    } catch(...) {return 2;}
}
