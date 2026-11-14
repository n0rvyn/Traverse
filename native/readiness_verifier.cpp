#include "readiness_verifier.hpp"
#include "endpoint_settings.hpp"
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <memory>
#include <set>
#include <httplib.h>
#include <openssl/crypto.h>
#include <array>
#include <cstring>
#include <initializer_list>
#include <stdexcept>

namespace traverse {
namespace {
using json=nlohmann::json;
void fields(const json &value,std::initializer_list<const char *> keys) {
    if(!value.is_object() || value.size()!=keys.size())throw std::runtime_error("Invalid shape");
    for(auto key:keys)if(!value.contains(key))throw std::runtime_error("Missing field");
}
void version(const json &value) {
    const auto &v=value.at("schemaVersion");
    if(!v.is_number_integer() || v!=1)throw std::runtime_error("Invalid version");
}
std::string text(const json &value,const char *key) {
    auto result=value.at(key).get<std::string>();
    if(result.find_first_of("\r\n")!=std::string::npos || result.find('\0')!=std::string::npos)
        throw std::runtime_error("Invalid text");
    return result;
}
std::string hex(const json &value,const char *key,std::size_t length) {
    auto result=text(value,key);
    if(result.size()!=length || result.find_first_not_of("0123456789abcdef")!=std::string::npos)
        throw std::runtime_error("Invalid lease");
    return result;
}
bool same(const std::string &a,const std::string &b) {
    return a.size()==b.size() && !a.empty() && CRYPTO_memcmp(a.data(),b.data(),a.size())==0;
}
json failed(const char *status) { return {{"schemaVersion",1},{"status",status}}; }
}
std::string canonical_readiness_address(const std::string &address) {
    in_addr v4{};in6_addr v6{};std::array<char,INET6_ADDRSTRLEN> buffer{};
    if(inet_pton(AF_INET,address.c_str(),&v4)==1) {
        auto bits=ntohl(v4.s_addr);
        if(bits==0 || (bits&0xf0000000u)==0xe0000000u || bits==0xffffffffu)
            throw std::runtime_error("Invalid unicast pin");
        inet_ntop(AF_INET,&v4,buffer.data(),buffer.size());
    } else if(inet_pton(AF_INET6,address.c_str(),&v6)==1) {
        if(IN6_IS_ADDR_UNSPECIFIED(&v6) || IN6_IS_ADDR_MULTICAST(&v6))
            throw std::runtime_error("Invalid unicast pin");
        if(IN6_IS_ADDR_V4MAPPED(&v6)) {
            std::uint32_t mapped;std::memcpy(&mapped,v6.s6_addr+12,4);mapped=ntohl(mapped);
            if(mapped==0 || (mapped&0xf0000000u)==0xe0000000u || mapped==0xffffffffu)
                throw std::runtime_error("Invalid mapped unicast pin");
        }
        inet_ntop(AF_INET6,&v6,buffer.data(),buffer.size());
    } else throw std::runtime_error("Numeric pin required");
    return buffer.data();
}
std::vector<std::string> readiness_local_addresses(const std::string &listen,const std::string &advertised) {
    const int family=advertised.find(':')==std::string::npos?AF_INET:AF_INET6;
    if(listen!="0.0.0.0" && listen!="::") {
        auto address=canonical_readiness_address(listen);
        if((address.find(':')==std::string::npos)!=(family==AF_INET))throw std::runtime_error("Observer family unavailable");
        return {address};
    }
    ifaddrs *raw=nullptr;
    if(getifaddrs(&raw))throw std::runtime_error("Observer interfaces unavailable");
    std::unique_ptr<ifaddrs,decltype(&freeifaddrs)> interfaces(raw,freeifaddrs);
    std::set<std::string> result;
    for(auto *item=raw;item;item=item->ifa_next) {
        if(!item->ifa_addr || item->ifa_addr->sa_family!=family || !(item->ifa_flags&IFF_UP) || (item->ifa_flags&IFF_LOOPBACK))continue;
        const void *address=family==AF_INET?static_cast<const void *>(&reinterpret_cast<sockaddr_in *>(item->ifa_addr)->sin_addr):
            static_cast<const void *>(&reinterpret_cast<sockaddr_in6 *>(item->ifa_addr)->sin6_addr);
        if(family==AF_INET6 && IN6_IS_ADDR_LINKLOCAL(static_cast<const in6_addr *>(address)))continue;
        char text[INET6_ADDRSTRLEN];
        if(!inet_ntop(family,address,text,sizeof(text)))throw std::runtime_error("Observer interface invalid");
        result.insert(canonical_readiness_address(text));
    }
    if(result.empty())throw std::runtime_error("Observer family unavailable");
    return {result.begin(),result.end()};
}
ReadinessTarget parse_readiness_target(const json &target) {
    if(target.contains("relayCaFile"))fields(target,{"host","port","basePath","address","caFile","relayCaFile"});
    else fields(target,{"host","port","basePath","address","caFile"});
    ReadinessTarget result;
    result.host=EndpointSettings::normalize_host(text(target,"host"));
    result.base_path=EndpointSettings::normalize_base_path(text(target,"basePath"));
    const auto &port=target.at("port");
    if(!port.is_number_integer() || port<1 || port>65535)throw std::runtime_error("Invalid port");
    result.port=port.get<int>();result.ca_file=text(target,"caFile");
    if(target.contains("relayCaFile"))result.relay_ca_file=text(target,"relayCaFile");
    result.address=canonical_readiness_address(text(target,"address"));
    result.origin="https://"+(result.host.find(':')==std::string::npos?result.host:"["+result.host+"]")+
        (result.port==443?"":":"+std::to_string(result.port));
    return result;
}
ReadinessVerification parse_readiness_verification(const json &request) {
    fields(request,{"schemaVersion","target","lease"});version(request);
    const auto &lease=request.at("lease");
    fields(lease,{"instance","id","token","nonce"});
    ReadinessVerification result;
    result.target=parse_readiness_target(request.at("target"));
    // Already-owned members clean up if validating a later field throws.
    result.lease.instance=hex(lease,"instance",32);
    result.lease.id=hex(lease,"id",32);
    result.lease.token=hex(lease,"token",64);
    result.lease.nonce=hex(lease,"nonce",64);
    return result;
}
ReadinessChallenge::Receipt parse_readiness_receipt(const json &response,const ReadinessChallenge::Lease &lease) {
    fields(response,{"schemaVersion","receipt"});version(response);
    const auto &r=response.at("receipt");fields(r,{"instance","id","nonce","observedMonotonicMs"});
    auto instance=hex(r,"instance",32),id=hex(r,"id",32),nonce=hex(r,"nonce",64);
    const auto &stamp=r.at("observedMonotonicMs");
    if(!stamp.is_number_integer() || stamp<0 || stamp>INT64_MAX ||
       !same(instance,lease.instance) || !same(id,lease.id) || !same(nonce,lease.nonce))
        throw std::runtime_error("Invalid receipt");
    return {instance,id,nonce,stamp.get<std::int64_t>()};
}
json validate_media_received(const json &event,const std::string &nonce,bool observer,const std::string &peer) {
    fields(event,{"schemaVersion","peer","port","type","nonce","videoDecoded","dataVerified","dtlsConnected","transport"});
    version(event);
    auto identity=hex(event,"peer",32);
    if((!peer.empty() && identity!=peer) || event.at("type")!="received" ||
       !same(hex(event,"nonce",64),nonce) || !event.at("port").is_number_integer() ||
       event.at("port")<1 || event.at("port")>65535)
        throw std::runtime_error("Invalid media identity");
    for(auto key:{"videoDecoded","dataVerified","dtlsConnected"})
        if(!event.at(key).is_boolean())throw std::runtime_error("Invalid media evidence");
    if(event.at("videoDecoded")!=observer || event.at("dataVerified")!=true || event.at("dtlsConnected")!=true)
        throw std::runtime_error("Incomplete media evidence");
    const auto &transport=event.at("transport");fields(transport,{"local","remote"});
    for(auto key:{"local","remote"}) {
        const auto &candidate=transport.at(key);fields(candidate,{"address","port","type","protocol"});
        auto address=text(candidate,"address");
        if(canonical_readiness_address(address)!=address || candidate.at("protocol")!="udp" ||
           !candidate.at("port").is_number_integer() || candidate.at("port")<1 || candidate.at("port")>65535 ||
           !candidate.at("type").is_number_integer() || candidate.at("type")<0 || candidate.at("type")>3)
            throw std::runtime_error("Invalid media transport");
    }
    return event;
}
json parse_media_receipt(const json &receipt,const ReadinessChallenge::Lease &lease,
                         const std::string &mode,unsigned short observer_port) {
    fields(receipt,{"schemaVersion","instance","id","nonce","mode","observerPort","observedMonotonicMs","media","cleanup"});
    if(!receipt.at("schemaVersion").is_number_integer() || receipt.at("schemaVersion")!=2 ||
       (mode!="direct" && mode!="relay") || receipt.at("mode")!=mode || !observer_port ||
       !receipt.at("observerPort").is_number_integer() || receipt.at("observerPort")!=observer_port ||
       !receipt.at("cleanup").is_boolean() || receipt.at("cleanup")!=true)
        throw std::runtime_error("Invalid media receipt");
    const auto &stamp=receipt.at("observedMonotonicMs");
    if(!stamp.is_number_integer() || stamp<0 || stamp>INT64_MAX ||
       !same(hex(receipt,"instance",32),lease.instance) || !same(hex(receipt,"id",32),lease.id) ||
       !same(hex(receipt,"nonce",64),lease.nonce))throw std::runtime_error("Wrong media receipt identity");
    auto media=validate_media_received(receipt.at("media"),lease.nonce,true);
    if(media.at("port")!=observer_port ||
       media.at("transport").at("local").at("type")!=(mode=="relay"?3:0) ||
       media.at("transport").at("remote").at("type")!=0)
        throw std::runtime_error("Wrong media path");
    return receipt;
}
void validate_media_exchange(const json &receipt,const json &source,const ReadinessChallenge::Lease &lease,
                             const std::string &mode,unsigned short observer_port,unsigned short source_port) {
    (void)parse_media_receipt(receipt,lease,mode,observer_port);
    (void)validate_media_received(source,lease.nonce,false,lease.id);
    const auto &receiver=receipt.at("media").at("transport"), &sender=source.at("transport");
    if(!source_port || source.at("port")!=source_port || sender.at("local").at("port")!=source_port ||
       sender.at("local").at("type")!=0 || receiver.at("remote").at("port")!=source_port)
        throw std::runtime_error("Wrong source endpoint");
    if(mode=="relay") {
        for(auto key:{"address","port"})
            if(receiver.at("local").at(key)!=sender.at("remote").at(key) ||
               receiver.at("remote").at(key)!=sender.at("local").at(key))
                throw std::runtime_error("Uncorroborated relay allocation");
    } else if(receiver.at("local").at("port")!=observer_port || sender.at("remote").at("port")!=observer_port)
        throw std::runtime_error("Wrong direct endpoint");
    // Direct peers can observe different IPs across NAT. Exact numeric grants
    // remain enforced by each native transport; do not equate private/public IPs.
}
json verify_readiness(const ReadinessVerification &request) {
    httplib::SSLClient client(request.target.host,request.target.port);
    client.set_hostname_addr_map({{request.target.host,request.target.address}});
    client.enable_server_certificate_verification(true);
    client.enable_server_hostname_verification(true);
    client.set_follow_location(false);client.set_keep_alive(false);client.set_decompress(false);
    if(!request.target.ca_file.empty())client.set_ca_cert_path(request.target.ca_file);
    httplib::Headers headers{{"Origin",request.target.origin},{"Authorization","Bearer "+request.lease.token}};
    json body={{"schemaVersion",1},{"id",request.lease.id},{"nonce",request.lease.nonce}};
    auto response=client.Post(request.target.base_path+"api/readiness/challenge",headers,body.dump(),"application/json");
    if(!response) {
        switch(response.error()) {
            case httplib::Error::SSLConnection:
            case httplib::Error::SSLLoadingCerts:
            case httplib::Error::SSLServerVerification:
            case httplib::Error::SSLServerHostnameVerification:return failed("tlsFailed");
            default:return failed("connectionFailed");
        }
    }
    if(response->status!=200)return failed("httpRejected");
    try {
        auto receipt=parse_readiness_receipt(json::parse(response->body),request.lease);
        return {{"schemaVersion",1},{"status","received"},{"receipt",{
            {"instance",receipt.instance},{"id",receipt.id},{"nonce",receipt.nonce},
            {"observedMonotonicMs",receipt.observed_monotonic_ms}}}};
    } catch(...) { return failed("invalidReceipt"); }
}
}
