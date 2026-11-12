#include "readiness_verifier.hpp"
#include "endpoint_settings.hpp"
#include <arpa/inet.h>
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
ReadinessTarget parse_readiness_target(const json &target) {
    fields(target,{"host","port","basePath","address","caFile"});
    ReadinessTarget result;
    result.host=EndpointSettings::normalize_host(text(target,"host"));
    result.base_path=EndpointSettings::normalize_base_path(text(target,"basePath"));
    const auto &port=target.at("port");
    if(!port.is_number_integer() || port<1 || port>65535)throw std::runtime_error("Invalid port");
    result.port=port.get<int>();result.ca_file=text(target,"caFile");
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
