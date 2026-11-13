#include "readiness_relay.hpp"
#include <csignal>
#include <iostream>
#include <nlohmann/json.hpp>
using json=nlohmann::json;
json snapshot(const traverse::ProbeTlsRelay &relay){auto s=relay.snapshot();return {{"started",s.started},{"verified",s.verified},{"finished",s.finished},{"failed",s.failed}};}
int main(){
    std::signal(SIGPIPE,SIG_IGN);
    try {
        std::string line;std::getline(std::cin,line);auto c=json::parse(line);
        traverse::ProbeTlsEndpoint endpoint{c.at("address"),c.at("hostname"),c.at("ca"),c.at("alpn"),c.at("port").get<std::uint16_t>()};
        traverse::ProbeTlsRelay relay(endpoint);
        std::cout<<json({{"port",relay.port()}}).dump()<<std::endl;
        while(std::getline(std::cin,line)) {
            auto command=json::parse(line);
            if(command.at("op")=="stop")relay.stop();
            else if(command.at("op")!="inspect")return 2;
            std::cout<<snapshot(relay).dump()<<std::endl;
        }
        relay.stop();return 0;
    }catch(const std::exception &error){std::cerr<<error.what()<<std::endl;return 1;}
}
