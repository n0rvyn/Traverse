#include "observer_policy.hpp"
#include "endpoint_settings.hpp"
#include <arpa/inet.h>
#include <filesystem>
#include <initializer_list>
#include <memory>
#include <netdb.h>

namespace traverse {
namespace {
using json=nlohmann::json;
void fields(const json &value,std::initializer_list<const char *> keys) {
    if(!value.is_object() || value.size()!=keys.size())throw std::runtime_error("Invalid observer shape");
    for(auto key:keys)if(!value.contains(key))throw std::runtime_error("Missing observer field");
}
void version(const json &value,int expected) {
    const auto &v=value.at("schemaVersion");
    if(!v.is_number_integer() || v!=expected)throw std::runtime_error("Invalid observer version");
}
std::string text(const json &value,const char *key) {
    auto result=value.at(key).get<std::string>();
    if(result.find_first_of("\r\n")!=std::string::npos || result.find('\0')!=std::string::npos)
        throw std::runtime_error("Invalid observer text");
    return result;
}
std::string hex(const json &value,const char *key,std::size_t length) {
    auto result=text(value,key);
    if(result.size()!=length || result.find_first_not_of("0123456789abcdef")!=std::string::npos)
        throw std::runtime_error("Invalid registration credential");
    return result;
}
ResolutionTarget resolution_target(const json &value) {
    fields(value,{"host","allowedAddresses"});
    ResolutionTarget result;
    result.host=EndpointSettings::normalize_host(text(value,"host"));
    const auto &addresses=value.at("allowedAddresses");
    if(!addresses.is_array() || addresses.empty())throw std::runtime_error("Empty address grant");
    for(const auto &address:addresses) {
        auto normalized=canonical_readiness_address(address.get<std::string>());
        if(!result.allowed_addresses.insert(normalized).second)throw std::runtime_error("Duplicate address grant");
    }
    return result;
}

}
ObserverConfiguration ObserverConfiguration::parse(const json &configuration) {
    fields(configuration,{"schemaVersion","listenAddress","port","certificate","privateKey","registrations"});
    version(configuration,1);ObserverConfiguration result;
    result.listen_address=text(configuration,"listenAddress");
    in_addr v4{};in6_addr v6{};
    if(inet_pton(AF_INET,result.listen_address.c_str(),&v4)!=1 &&
       inet_pton(AF_INET6,result.listen_address.c_str(),&v6)!=1)throw std::runtime_error("Invalid listen address");
    const auto &port=configuration.at("port");
    if(!port.is_number_integer() || port<1 || port>65535)throw std::runtime_error("Invalid observer port");
    result.port=port.get<int>();result.certificate=text(configuration,"certificate");
    result.private_key=text(configuration,"privateKey");
    if(!std::filesystem::path(result.certificate).is_absolute() || !std::filesystem::path(result.private_key).is_absolute())
        throw std::runtime_error("Absolute TLS paths required");
    const auto &rows=configuration.at("registrations");
    if(!rows.is_array())throw std::runtime_error("Invalid registry");
    std::set<std::string> tokens;
    for(const auto &row:rows) {
        fields(row,{"id","token","target"});
        ObserverRegistration registration;registration.id=hex(row,"id",32);registration.token=hex(row,"token",64);
        const auto &target=row.at("target");fields(target,{"host","port","basePath","caFile","allowedAddresses"});
        registration.resolution=resolution_target({{"host",target.at("host")},{"allowedAddresses",target.at("allowedAddresses")}});
        registration.target=parse_readiness_target({{"host",target.at("host")},{"port",target.at("port")},
            {"basePath",target.at("basePath")},{"caFile",target.at("caFile")},
            {"address",*registration.resolution.allowed_addresses.begin()}});
        if(!tokens.insert(registration.token).second || !result.registrations.emplace(registration.id,registration).second)
            throw std::runtime_error("Duplicate registry authority");
    }
    return result;
}
json ObserverRegistration::verification(const std::string &address,const json &lease) const {
    auto pin=canonical_readiness_address(address);
    if(!resolution.allowed_addresses.count(pin))throw std::runtime_error("Unregistered address");
    json request={{"schemaVersion",1},{"target",{{"host",target.host},{"port",target.port},
        {"basePath",target.base_path},{"caFile",target.ca_file},{"address",pin}}},{"lease",lease}};
    (void)parse_readiness_verification(request); // Same complete lease/target contract as worker.
    return request;
}
json ObserverRegistration::resolution_request() const {
    return {{"schemaVersion",2},{"operation","resolve"},{"target",{
        {"host",resolution.host},{"allowedAddresses",resolution.allowed_addresses}}}};
}
ResolutionTarget parse_resolution_request(const json &request) {
    fields(request,{"schemaVersion","operation","target"});version(request,2);
    if(text(request,"operation")!="resolve")throw std::runtime_error("Invalid operation");
    return resolution_target(request.at("target"));
}
}
