#include "readiness_media_transport.hpp"
#include <gst/gst.h>
#include <iostream>
#include <stdexcept>
using json=nlohmann::json;
#define CHECK(value) do { if(!(value))throw std::runtime_error("Check failed: " #value); } while(false)
template<class F>void rejects(F action){bool caught=false;try{action();}catch(const std::exception &){caught=true;}CHECK(caught);}
std::string sdp(){return "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\na=group:BUNDLE video0 application1\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\nc=IN IP4 0.0.0.0\r\na=mid:video0\r\na=recvonly\r\na=rtcp-mux\r\na=rtcp:9 IN IP4 0.0.0.0\r\na=candidate:x 1 UDP 100 127.0.0.1 33333 typ host\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r\na=mid:application1\r\na=sctp-port:5000\r\n";}
std::string replace(std::string text,const std::string &from,const std::string &to){auto at=text.find(from);CHECK(at!=std::string::npos);text.replace(at,from.size(),to);return text;}
int main(){
    gst_init(nullptr,nullptr);
    json base={{"schemaVersion",1},{"peer",std::string(32,'a')},{"nonce",std::string(64,'b')},{"role","source"},{"port",33332},{"addresses",{"127.0.0.1"}},{"peers",{{{"address","127.0.0.1"},{"port",33333}},{{"address","::1"},{"port",33334}}}}};
    auto config=traverse::ReadinessMediaConfig::parse(base);
    CHECK(config.source && config.port==33332 && config.peers.size()==2);
    CHECK(config.admit_candidate("").empty());
    CHECK(config.admit_candidate("candidate:x 1 UDP 100 ::ffff:127.0.0.1 33333 typ host")=="candidate:x 1 UDP 100 127.0.0.1 33333 typ host");
    CHECK(config.admit_candidate("candidate:x 1 udp 100 ::1 33334 typ relay raddr 0.0.0.0 rport 0")=="candidate:x 1 udp 100 ::1 33334 typ relay raddr 0.0.0.0 rport 0");
    for(const auto &value:{" ","candidate:x 1 UDP 100 foreign.local 33333 typ host","candidate:x 1 UDP 100 127.0.0.2 33333 typ host","candidate:x 1 UDP 100 127.0.0.1 33334 typ host","candidate:x 2 UDP 100 127.0.0.1 33333 typ host","candidate:x 1 TCP 100 127.0.0.1 33333 typ host tcptype active","candidate:x 1 UDP 100 127.0.0.1 33333 typ host raddr private.local","candidate:x 1 UDP 100 127.0.0.1 33333 typ host\r\na=control:other"})rejects([&]{config.admit_candidate(value);});
    for(auto value:{json("localhost"),json("0.0.0.0"),json("ff02::1"),json(std::string("127.0.0.1\0bad",13))}){auto bad=base;bad["addresses"]={value};rejects([&]{traverse::ReadinessMediaConfig::parse(bad);});}
    {auto mapped=base;mapped["addresses"]={"::ffff:127.0.0.1"};auto canonical=traverse::ReadinessMediaConfig::parse(mapped);CHECK(canonical.addresses==std::vector<std::string>{"127.0.0.1"});}
    {auto duplicate=base;duplicate["addresses"]={"127.0.0.1","::ffff:127.0.0.1"};rejects([&]{traverse::ReadinessMediaConfig::parse(duplicate);});}
    {auto bad=base;bad["controllerToken"]="not-a-probe-field";rejects([&]{traverse::ReadinessMediaConfig::parse(bad);});}
    {auto mapped=base;mapped["advertisedAddress"]="192.0.2.7";CHECK(traverse::ReadinessMediaConfig::parse(mapped).advertised_address=="192.0.2.7");
        for(const auto *address:{"external.test","0.0.0.0","ff02::1","2001:db8::1"}){
            mapped["advertisedAddress"]=address;rejects([&]{traverse::ReadinessMediaConfig::parse(mapped);});}}
    {auto bad=base;bad["relay"]={{"port",44444},{"username",std::string(64,'a')},{"credential",std::string(64,'b')}};rejects([&]{traverse::ReadinessMediaConfig::parse(bad);});bad["role"]="observer";CHECK(traverse::ReadinessMediaConfig::parse(bad).relay.has_value());
        auto alias=bad;alias["advertisedAddress"]="192.0.2.7";rejects([&]{traverse::ReadinessMediaConfig::parse(alias);});
        bad["relay"]["host"]="external.test";rejects([&]{traverse::ReadinessMediaConfig::parse(bad);});}
    CHECK(config.admit_description(sdp())==sdp());
    CHECK(config.admit_description(replace(sdp(),"127.0.0.1 33333 typ host","::ffff:127.0.0.1 33333 typ host"))==sdp());
    for(const auto &bad:{replace(sdp(),"a=recvonly","a=sendrecv"),replace(sdp(),"a=recvonly","a=recvonly\r\na=sendrecv"),replace(sdp(),"a=rtcp-mux\r\n",""),replace(sdp(),"BUNDLE video0 application1","BUNDLE application1 video0"),replace(sdp(),"127.0.0.1 33333 typ host","private.local 33333 typ host"),replace(sdp(),"c=IN IP4 0.0.0.0","c=IN IP4 private.local"),replace(sdp(),"o=- 1 1 IN IP4 0.0.0.0","o=- 1 1 IN IP4 private.local"),replace(sdp(),"a=mid:video0","a=mid:video0\r\na=remote-candidates:1 127.0.0.1 55555"),replace(sdp(),"s=-","s=-\r\na=remote-candidates:1 private.local 33333"),replace(sdp(),"a=rtcp:9 IN IP4 0.0.0.0","a=rtcp:9 IN IP4 private.local"),replace(sdp(),"m=video 9 UDP/TLS/RTP/SAVPF 96","m=audio 9 UDP/TLS/RTP/SAVPF 96")})rejects([&]{config.admit_description(bad);});
    auto observer=base;observer["role"]="observer";auto receiver=traverse::ReadinessMediaConfig::parse(observer);
    CHECK(receiver.admit_description(replace(sdp(),"a=recvonly","a=sendonly"))==replace(sdp(),"a=recvonly","a=sendonly"));
    rejects([&]{receiver.admit_description(sdp());});
    std::cout<<"Private media config, numeric candidate and single-BUNDLE SDP admission passed\n";
}
