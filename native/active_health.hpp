#pragma once
#include "common.hpp"
#include <cmath>
#include <optional>

namespace traverse {
// One actual peer's DTLS health channel. Caller serializes access separately
// from input. This object has no IPC/input/capture authority or timers.
class ActiveHealth {
    const unsigned long generation;
    const std::string epoch=random_secret(16);
    std::string nonce;
    std::int64_t issued=0;
    std::uint64_t decoded=0,presented=0;
    json last=nullptr;
    static void fields(const json &value,std::initializer_list<const char *> keys) {
        if(!value.is_object() || value.size()!=keys.size())throw std::runtime_error("Invalid health shape");
        for(auto key:keys)if(!value.contains(key))throw std::runtime_error("Missing health field");
    }
    static std::uint64_t integer(const json &value,bool positive=false) {
        if(!value.is_number_integer() || value<(positive?1:0) || value>INT64_MAX)
            throw std::runtime_error("Invalid health counter");
        return value.get<std::uint64_t>();
    }
  public:
    std::uint64_t rejected=0;
    explicit ActiveHealth(unsigned long peer_generation):generation(peer_generation){}
    std::optional<json> receive(const json &message,bool connected) {
        if(!message.at("schemaVersion").is_number_integer() || message.at("schemaVersion")!=1)
            throw std::runtime_error("Invalid health version");
        if(!connected)return std::nullopt;
        if(message.at("type")=="request") {
            fields(message,{"schemaVersion","type"});
            if(nonce.empty()) {
                nonce=random_secret(32);
                issued=std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count();
            }
            return json{{"schemaVersion",1},{"type","challenge"},{"generation",generation},
                {"epoch",epoch},{"nonce",nonce},{"issuedMonotonicMs",issued}};
        }
        fields(message,{"schemaVersion","type","generation","epoch","nonce","issuedMonotonicMs",
            "baselineDecodedFrames","decodedFrames","presentedFrames","mediaTime","width","height","transport"});
        if(message.at("type")!="receipt" || nonce.empty() || integer(message.at("generation"),true)!=generation ||
           !equal_secret(message.at("epoch").get<std::string>(),epoch) ||
           !equal_secret(message.at("nonce").get<std::string>(),nonce) ||
           integer(message.at("issuedMonotonicMs"))!=static_cast<std::uint64_t>(issued))
            throw std::runtime_error("Stale health receipt");
        auto baseline=integer(message.at("baselineDecodedFrames"));
        auto next_decoded=integer(message.at("decodedFrames"),true),next_presented=integer(message.at("presentedFrames"),true);
        if(baseline<decoded || next_decoded<=baseline || next_presented<=presented)
            throw std::runtime_error("No fresh decoded frame");
        (void)integer(message.at("width"),true);(void)integer(message.at("height"),true);
        if(!message.at("mediaTime").is_number() || !std::isfinite(message.at("mediaTime").get<double>()) || message.at("mediaTime")<0)
            throw std::runtime_error("Invalid decoded frame");
        const auto &transport=message.at("transport");fields(transport,{"protocol","localType","remoteType","dtlsState"});
        if((transport.at("protocol")!="udp" && transport.at("protocol")!="tcp") || transport.at("dtlsState")!="connected")
            throw std::runtime_error("No connected media transport");
        for(auto key:{"localType","remoteType"})
            if(transport.at(key)!="host" && transport.at(key)!="srflx" && transport.at(key)!="prflx" && transport.at(key)!="relay")
                throw std::runtime_error("Invalid selected transport");
        decoded=next_decoded;presented=next_presented;
        last={{"issuedMonotonicMs",issued},{"observedMonotonicMs",std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count()},
            {"decodedFrames",decoded},{"presentedFrames",presented},{"mediaTime",message.at("mediaTime")},
            {"width",message.at("width")},{"height",message.at("height")},{"transport",transport}};
        nonce.clear();return std::nullopt;
    }
    void close(){nonce.clear();}
    json snapshot(bool open) const {
        json result={{"schemaVersion",1},{"generation",generation},{"status",!open?"unavailable":last.is_null()?"waiting":"observed"},
            {"pending",open && !nonce.empty()},{"rejected",rejected}};
        if(!last.is_null())result["lastObservation"]=last;
        return result;
    }
};
}
