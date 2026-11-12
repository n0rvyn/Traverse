#include "readiness_agent.hpp"
#include <charconv>
#include <csignal>
#include <iostream>
#include <sys/prctl.h>
#include <unistd.h>

int main(int argc,char **argv) {
    try {
        if(argc!=3 || std::string(argv[1])!="--supervisor-pid")return 1;
        pid_t parent=-1;auto end=argv[2]+std::char_traits<char>::length(argv[2]);
        auto parsed=std::from_chars(argv[2],end,parent);
        if(parsed.ec!=std::errc{} || parsed.ptr!=end || parent<=1 ||
           prctl(PR_SET_PDEATHSIG,SIGTERM) || getppid()!=parent)return 1;
        std::string input(std::istreambuf_iterator<char>(std::cin),{});
        traverse::run_readiness_agent(nlohmann::json::parse(input),[](const auto &event){
            std::cout<<event.dump()<<'\n'<<std::flush;
            if(!std::cout)throw std::runtime_error("Private event channel closed");
        });
        return 0;
    } catch(...) {
        // No exception, credential, remote response or configuration enters logs.
        std::cout<<"{\"schemaVersion\":1,\"event\":\"error\",\"status\":\"agentFailed\"}\n"<<std::flush;
        return 1;
    }
}
