#include "readiness_verifier.hpp"
#include <functional>
#include <iostream>
#include <stdexcept>
using nlohmann::json;
void require(bool ok,const char *message) { if(!ok)throw std::runtime_error(message); }
void rejected(const std::function<void()> &fn) {
    bool failed=false;try{fn();}catch(...){failed=true;}require(failed,"Invalid contract accepted");
}
int main() {
    try {
        json input={{"schemaVersion",1},{"target",{{"host","Example.TEST"},{"port",443},
            {"basePath","/traverse/v1.2/"},{"address","127.0.0.1"},{"caFile",""}}},
            {"lease",{{"instance",std::string(32,'a')},{"id",std::string(32,'b')},
                {"token",std::string(64,'c')},{"nonce",std::string(64,'d')}}}};
        auto parsed=traverse::parse_readiness_verification(input);
        require(parsed.target.host=="example.test" && parsed.target.origin=="https://example.test" &&
            parsed.target.base_path=="/traverse/v1.2/","Canonical target wrong");
        auto custom=input;custom["target"]["port"]=8443;
        require(traverse::parse_readiness_verification(custom).target.origin=="https://example.test:8443","Custom port origin wrong");
        custom["target"]["host"]="[::1]";custom["target"]["address"]="::1";
        require(traverse::parse_readiness_verification(custom).target.origin=="https://[::1]:8443","IPv6 origin wrong");
        for(auto port:std::vector<json>{0,-1,65536,1.5,"443",true,UINT64_MAX}) {
            auto bad=input;bad["target"]["port"]=port;rejected([&]{traverse::parse_readiness_verification(bad);});
        }
        for(auto address:{"hostname.test","127.1","0.0.0.0","224.0.0.1","255.255.255.255","::","ff02::1","fe80::1%eth0","::ffff:224.0.0.1"}) {
            auto bad=input;bad["target"]["address"]=address;rejected([&]{traverse::parse_readiness_verification(bad);});
        }
        for(auto host:{"https://example.test","a@b.test","x.test?foo","x.test\r\nX:1"}) {
            auto bad=input;bad["target"]["host"]=host;rejected([&]{traverse::parse_readiness_verification(bad);});
        }
        for(auto key:{"instance","id","token","nonce"}) {
            auto bad=input;bad["lease"][key]="z";rejected([&]{traverse::parse_readiness_verification(bad);});
        }
        auto bad=input;bad["schemaVersion"]=1.0;rejected([&]{traverse::parse_readiness_verification(bad);});
        bad=input;bad["extra"]=1;rejected([&]{traverse::parse_readiness_verification(bad);});
        json response={{"schemaVersion",1},{"receipt",{{"instance",parsed.lease.instance},{"id",parsed.lease.id},
            {"nonce",parsed.lease.nonce},{"observedMonotonicMs",123}}}};
        require(traverse::parse_readiness_receipt(response,parsed.lease).observed_monotonic_ms==123,"Valid receipt rejected");
        for(auto key:{"instance","id","nonce"}) {
            bad=response;bad["receipt"][key]=std::string(key==std::string("nonce")?64:32,'0');
            rejected([&]{traverse::parse_readiness_receipt(bad,parsed.lease);});
        }
        for(auto stamp:std::vector<json>{-1,1.0,"123",UINT64_MAX}) {
            bad=response;bad["receipt"]["observedMonotonicMs"]=stamp;
            rejected([&]{traverse::parse_readiness_receipt(bad,parsed.lease);});
        }
        bad=response;bad["receipt"]["token"]=parsed.lease.token;
        rejected([&]{traverse::parse_readiness_receipt(bad,parsed.lease);});
        std::cout<<"Verifier target, numeric pin, version and exact receipt contracts passed\n";
        return 0;
    }catch(const std::exception &error){std::cerr<<error.what()<<'\n';return 1;}
}
