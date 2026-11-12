#include "readiness_network.hpp"
#include <iostream>
#include <nlohmann/json.hpp>
int main(int argc,char **argv) {
    try {
        std::vector<std::string> files;for(int i=1;i<argc;++i)files.emplace_back(argv[i]);
        traverse::ReadinessNetwork network(std::move(files));std::cout<<"ready\n"<<std::flush;
        std::string line;
        while(std::getline(std::cin,line)) {
            if(line!="poll")return 1;
            auto result=network.poll();
            std::cout<<nlohmann::json{{"changed",result.changed},{"healthy",result.healthy}}.dump()<<'\n'<<std::flush;
        }
        return 0;
    }catch(const std::exception &error){std::cerr<<error.what()<<'\n';return 1;}
}
