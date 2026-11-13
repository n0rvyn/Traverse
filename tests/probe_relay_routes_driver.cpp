#include "tls_router.hpp"
#include "probe_relay_routes.hpp"
#include "probe_relay_broker.hpp"
#include <csignal>
#include <iostream>
#include <nlohmann/json.hpp>
#include <unistd.h>
int main() {
    std::signal(SIGPIPE,SIG_IGN);
    try {
        std::string line;std::getline(std::cin,line);auto config=nlohmann::json::parse(line);
        auto routes=std::make_shared<traverse::ProbeRelayRoutes>();
        const bool broker=config.value("broker",false);
        if(!broker)routes->install(config.at("lease"),config.at("backend"));
        traverse::TlsRouterConfig settings;
        settings.address="127.0.0.1";settings.expected_host="localhost";
        settings.certificate=config.at("cert");settings.private_key=config.at("key");
        settings.ca_file=config.at("ca");settings.http_port=config.at("http");settings.turn_port=config.at("turn");
        settings.probe_routes=routes;
        if(broker){settings.probe_socket=config.at("brokerPath");settings.probe_owner_pid=getpid();}
        traverse::TlsRouter router(settings);
        std::atomic<bool> cancel{false};
        std::map<std::string,std::unique_ptr<traverse::ProbeRelayLease>> leases;
        if(broker) {
            auto id=config.at("lease").get<std::string>();
            leases.emplace(id,std::make_unique<traverse::ProbeRelayLease>(settings.probe_socket,id,config.at("backend"),cancel));
        }
        std::cout<<nlohmann::json({{"port",router.port()}}).dump()<<std::endl;
        while(std::getline(std::cin,line)) {
            auto command=nlohmann::json::parse(line);
            if(command.at("op")=="revoke") {
                auto id=command.at("lease").get<std::string>();
                if(broker) {
                    auto it=leases.find(id);
                    if(it==leases.end() || !it->second->end(cancel))throw std::runtime_error("Relay end not acknowledged");
                    leases.erase(it);
                } else routes->revoke(id);
            }
            else if(command.at("op")=="install") {
                auto id=command.at("lease").get<std::string>();
                if(broker)leases.emplace(id,std::make_unique<traverse::ProbeRelayLease>(settings.probe_socket,id,command.at("backend"),cancel));
                else routes->install(id,command.at("backend"));
            }
            else return 2;
            std::cout<<"{\"ok\":true}"<<std::endl;
        }
        leases.clear();router.stop();return 0;
    }catch(const std::exception &error){std::cerr<<error.what()<<std::endl;return 1;}
}
