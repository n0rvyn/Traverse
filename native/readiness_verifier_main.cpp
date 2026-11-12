#include "readiness_verifier.hpp"
#include "observer_policy.hpp"
#include <iostream>
#include <charconv>
#include <csignal>
#include <sys/prctl.h>
#include <unistd.h>

int main(int argc,char **argv) {
    using nlohmann::json;
    json result={{"schemaVersion",1},{"status","invalidRequest"}};
    try {
        bool accepted=argc==1;
        if(argc==3 && std::string(argv[1])=="--supervisor-pid") {
            pid_t parent=-1;
            auto end=argv[2]+std::char_traits<char>::length(argv[2]);
            auto parsed=std::from_chars(argv[2],end,parent);
            accepted=parsed.ec==std::errc{} && parsed.ptr==end && parent>1 &&
                prctl(PR_SET_PDEATHSIG,SIGTERM)==0 && getppid()==parent;
        }
        if(accepted) {
            // The supervising caller owns this private input and closes it after
            // one request. Neither credentials nor receipt enter ordinary logs.
            std::string input(std::istreambuf_iterator<char>(std::cin),{});
            auto value=json::parse(input);
            if(value.is_object() && value.contains("schemaVersion") && value.at("schemaVersion")==2) {
                auto target=traverse::parse_resolution_request(value);
                try { result=traverse::resolve_readiness_dns(target); }
                catch(...) { result={{"schemaVersion",2},{"status","internalFailure"}}; }
            } else {
                auto request=traverse::parse_readiness_verification(value);
                try { result=traverse::verify_readiness(request); }
                catch(...) { result={{"schemaVersion",1},{"status","internalFailure"}}; }
            }
        }
    } catch(...) {}
    std::cout<<result.dump()<<'\n';
    return result.at("status")=="received" || result.at("status")=="resolved"?0:1;
}
