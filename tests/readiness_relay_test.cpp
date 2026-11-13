#include "readiness_relay.hpp"
#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <vector>
using Guard = traverse::ProbeTurnResponses;
using Bytes = Guard::Bytes;
#define CHECK(value) do { if (!(value)) throw std::runtime_error("Check failed: " #value); } while (false)
template<class F> void rejects(F action) { bool caught=false; try { action(); } catch(const std::exception &) { caught=true; } CHECK(caught); }
Bytes message(unsigned type, Bytes attributes = {}) {
    Bytes bytes{static_cast<unsigned char>(type>>8),static_cast<unsigned char>(type),
        static_cast<unsigned char>(attributes.size()>>8),static_cast<unsigned char>(attributes.size()),
        0x21,0x12,0xa4,0x42,0,1,2,3,4,5,6,7,8,9,10,11};
    bytes.resize(20+attributes.size());
    std::copy(attributes.begin(),attributes.end(),bytes.begin()+20); return bytes;
}
Bytes receive(Guard &g,const Bytes &bytes) { return g.receive(bytes.data(),bytes.size()); }
int main() {
    auto allocation=message(0x0103);
    auto unauthorized=message(0x0113,{0,9,0,4,0,0,4,1});
    auto data=message(0x0017,{0,0x13,0,3,1,2,3,0});
    Bytes channel{0x40,0,0,3,1,2,3,0};
    for(const auto &frame:{allocation,unauthorized,data,channel,Bytes{0x7f,0xff,0,0}}) {
        for(std::size_t split=0;split<=frame.size();++split) {
            Guard g;auto a=g.receive(frame.data(),split);auto b=g.receive(frame.data()+split,frame.size()-split);
            a.insert(a.end(),b.begin(),b.end());CHECK(a==frame);g.finish();
        }
    }
    Bytes combined;
    for(auto &value:{allocation,unauthorized,data,channel})combined.insert(combined.end(),value.begin(),value.end());
    {Guard g;CHECK(receive(g,combined)==combined);g.finish();}
    for(auto bad:{message(3),message(0x0113),message(0x0113,{0,9,0,4,0,0,3,0}),
            message(0x0103,{0x80,0x23,0,0}),message(0x0017,{0x80,0x23,0,0}),
            message(0x0103,{0,9,0,4,0,0,4,1}),message(0x0113,{0,9,0,4,0,0,0x83,0}),
            message(0x0113,{0,9,0,4,0,0,4,100}),message(0x0017,{0,0x13,0,9}),
            message(0x0113,{0,9,0,4,0,0,4,1,0,9,0,4,0,0,4,1}),Bytes{0x80,0,0,0}}) {
        Guard g;rejects([&]{receive(g,bad);});rejects([&]{receive(g,allocation);});rejects([&]{g.finish();});
    }
    {auto bad=allocation;bad[4]=0;Guard g;rejects([&]{receive(g,bad);});}
    {auto bad=allocation;bad[3]=1;Guard g;rejects([&]{receive(g,bad);});}
    for(std::size_t split=1;split<allocation.size();++split) {
        Guard g;CHECK(g.receive(allocation.data(),split).empty());rejects([&]{g.finish();});
    }
    {Guard g;rejects([&]{g.receive(nullptr,1);});}
    // Maximum wire-sized ChannelData is opaque; payloads can contain STUN-like
    // bytes without becoming messages. This is a framing bound, not an app cap.
    {Bytes big{0x40,0,0xff,0xff};big.resize(4+65536,0x80);Guard g;Bytes result;
     for(std::size_t offset=0;offset<big.size();offset+=137){auto n=std::min(std::size_t{137},big.size()-offset);auto part=g.receive(big.data()+offset,n);result.insert(result.end(),part.begin(),part.end());}
     CHECK(result==big);g.finish();}
    CHECK(traverse::probe_relay_alpn(std::string(64,'a'))=="traverse-probe/"+std::string(64,'a'));
    for(auto value:{std::string{},std::string(63,'a'),std::string(65,'a'),std::string(64,'A'),std::string(64,'/')})rejects([&]{traverse::probe_relay_alpn(value);});
    std::cout<<"Probe TLS response framing and redirect admission passed\n";
}
