#include "readiness_manager.hpp"
#include "common.hpp"
#include <charconv>

int main(int argc,char **argv) {
    try {
        if(argc!=3 || std::string(argv[1])!="--supervisor-pid")return 1;
        pid_t parent=-1;auto end=argv[2]+std::char_traits<char>::length(argv[2]);
        auto parsed=std::from_chars(argv[2],end,parent);
        if(parsed.ec!=std::errc{} || parsed.ptr!=end || parent<=1 || prctl(PR_SET_PDEATHSIG,SIGTERM) || getppid()!=parent)return 1;
        std::string bytes(std::istreambuf_iterator<char>(std::cin),{});auto input=json::parse(bytes);
        auto settings=traverse::ObserverSettings::parse(input.at("observer"),"");
        traverse::ReadinessManager manager(settings,input.at("agent").get<std::string>(),
            input.at("owner").at("socket").get<std::string>(),input.at("owner").at("pid").get<pid_t>());
        if(!manager.start() || manager.start())throw std::runtime_error("Overlapping start accepted");
        auto watchdog=Clock::now()+std::chrono::seconds(30);bool invalidated=false,retried=false;std::int64_t maximum=0;
        while(Clock::now()<watchdog) {
            auto start=Clock::now();manager.tick();
            maximum=std::max<std::int64_t>(maximum,std::chrono::duration_cast<std::chrono::microseconds>(Clock::now()-start).count());
            auto snapshot=manager.snapshot();auto status=snapshot.at("status").get<std::string>();
            if(input.value("invalidate",false) && !invalidated && !snapshot.at("addresses").empty()) {
                manager.invalidate();invalidated=true;continue;
            }
            if(status=="verified" || status=="partial" || status=="failed" || status=="unavailable" || status=="cleanupPending") {
                if(status=="cleanupPending" && input.value("retryCleanup",false) && !retried) {
                    if(!manager.start())throw std::runtime_error("Explicit cleanup retry rejected");
                    retried=true;continue;
                }
                std::cout<<json{{"snapshot",snapshot},{"invalidated",invalidated},{"cleanupRetried",retried},{"maximumTickUs",maximum}}.dump()<<'\n';
                return 0;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        throw std::runtime_error("Manager test watchdog expired");
    } catch(const std::exception &error){std::cerr<<error.what()<<'\n';return 1;}
}
