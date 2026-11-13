#include "readiness_probe_turn.hpp"
#include <iostream>
#include <csignal>
int main(int argc,char **argv) {
    std::signal(SIGPIPE,SIG_IGN);
    try {
        if(argc!=2)return 2;
        std::string text;
        if(!std::getline(std::cin,text))return 2;
        auto config=nlohmann::json::parse(text);
        traverse::ReadinessProbeTurn relay(argv[1],config.at("addresses").get<std::vector<std::string>>(),
            config.at("port").get<std::uint16_t>(),config.at("username"),config.at("credential"));
        std::cout<<nlohmann::json({{"port",relay.port()}}).dump()<<std::endl;
        while(std::getline(std::cin,text)) {
            auto request=nlohmann::json::parse(text);auto op=request.at("op").get<std::string>();
            if(op=="inspect") {
                auto ready=relay.ready();auto allocations=nlohmann::json::array();
                for(const auto &peer:relay.allocations())allocations.push_back({{"address",peer.address},{"port",peer.port}});
                std::cout<<nlohmann::json({{"ready",ready},{"allocations",allocations}}).dump()<<std::endl;
            } else if(op=="stop") {relay.stop();std::cout<<"{\"stopped\":true}"<<std::endl;return 0;}
            else return 2;
        }
        return 0;
    } catch(...) {std::cerr<<"Private relay test failed"<<std::endl;return 1;}
}
