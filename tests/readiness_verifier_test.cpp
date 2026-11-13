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
        json candidate={{"address","127.0.0.1"},{"port",12345},{"type",0},{"protocol","udp"}};
        json media={{"schemaVersion",1},{"peer",std::string(32,'e')},{"port",12345},{"type","received"},
            {"nonce",parsed.lease.nonce},{"videoDecoded",true},{"dataVerified",true},{"dtlsConnected",true},
            {"transport",{{"local",candidate},{"remote",candidate}}}};
        json receipt={{"schemaVersion",2},{"instance",parsed.lease.instance},{"id",parsed.lease.id},
            {"nonce",parsed.lease.nonce},{"mode","direct"},{"observerPort",12345},
            {"observedMonotonicMs",123},{"media",media},{"cleanup",true}};
        require(traverse::parse_media_receipt(receipt,parsed.lease,"direct",12345)==receipt,"Valid media rejected");
        auto relay=receipt;relay["mode"]="relay";relay["media"]["transport"]["local"]["type"]=3;
        require(traverse::parse_media_receipt(relay,parsed.lease,"relay",12345)==relay,"Valid relay rejected");
        for(auto key:{"instance","id","nonce"}) {
            bad=receipt;bad[key]=std::string(key==std::string("nonce")?64:32,'0');
            rejected([&]{traverse::parse_media_receipt(bad,parsed.lease,"direct",12345);});
        }
        for(auto key:{"videoDecoded","dataVerified","dtlsConnected"}) {
            for(auto value:std::vector<json>{false,1,"true"}) {
                bad=receipt;bad["media"][key]=value;
                rejected([&]{traverse::parse_media_receipt(bad,parsed.lease,"direct",12345);});
            }
        }
        for(auto pointer:{"/schemaVersion","/cleanup","/observerPort","/observedMonotonicMs",
                          "/media/port","/media/schemaVersion","/media/transport/local/port","/media/transport/remote/type"}) {
            bad=receipt;bad[json::json_pointer(pointer)]=1.5;
            rejected([&]{traverse::parse_media_receipt(bad,parsed.lease,"direct",12345);});
        }
        bad=receipt;bad["media"]["nonce"]=std::string(64,'0');
        rejected([&]{traverse::parse_media_receipt(bad,parsed.lease,"direct",12345);});
        bad=receipt;bad["media"]["transport"]["local"]["type"]=3;
        rejected([&]{traverse::parse_media_receipt(bad,parsed.lease,"direct",12345);});
        bad=receipt;bad["media"]["transport"]["remote"]["address"]="hostname.test";
        rejected([&]{traverse::parse_media_receipt(bad,parsed.lease,"direct",12345);});
        auto source=media;source["videoDecoded"]=false;source["peer"]=parsed.lease.id;
        require(traverse::validate_media_received(source,parsed.lease.nonce,false,parsed.lease.id)==source,"Source rejected");
        traverse::validate_media_exchange(receipt,source,parsed.lease,"direct",12345,12345);
        traverse::validate_media_exchange(relay,source,parsed.lease,"relay",12345,12345);
        auto unowned=source;unowned["transport"]["remote"]["port"]=12346;
        rejected([&]{traverse::validate_media_exchange(relay,unowned,parsed.lease,"relay",12345,12345);});
        unowned=source;unowned["nonce"]=std::string(64,'0');
        rejected([&]{traverse::validate_media_exchange(receipt,unowned,parsed.lease,"direct",12345,12345);});
        // Different NAT views do not invalidate the same fixed-port direct path.
        auto nat=source;nat["transport"]["local"]["address"]="192.0.2.10";
        nat["transport"]["remote"]["address"]="198.51.100.20";
        traverse::validate_media_exchange(receipt,nat,parsed.lease,"direct",12345,12345);
        rejected([&]{traverse::validate_media_received(media,parsed.lease.nonce,false,parsed.lease.id);});
        rejected([&]{traverse::parse_media_receipt(receipt,parsed.lease,"relay",12345);});
        rejected([&]{traverse::parse_media_receipt(receipt,parsed.lease,"direct",12346);});
        std::cout<<"Verifier target, numeric pin, version and exact HTTP/media receipt contracts passed\n";
        return 0;
    }catch(const std::exception &error){std::cerr<<error.what()<<'\n';return 1;}
}
