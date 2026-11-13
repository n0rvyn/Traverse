#include "name_resolution.hpp"
#include "endpoint_settings.hpp"
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netdb.h>
#include <array>
#include <algorithm>
#include <fstream>
#include <map>
#include <memory>
#include <sstream>
#include <vector>

namespace traverse {
namespace {
using nlohmann::json;
void fields(const json &value,std::initializer_list<const char *> keys) {
    if(!value.is_object() || value.size()!=keys.size())throw std::runtime_error("Invalid resolution evidence");
    for(auto key:keys)if(!value.contains(key))throw std::runtime_error("Missing resolution evidence");
}
std::string address(int family,const void *bytes,bool validate=true) {
    std::array<char,INET6_ADDRSTRLEN> output{};
    if(!inet_ntop(family,bytes,output.data(),output.size()))throw std::runtime_error("Invalid resolver address");
    return validate?canonical_readiness_address(output.data()):std::string(output.data());
}
json family(const char *status,const std::set<std::string> &addresses={}) {
    return {{"status",status},{"addresses",addresses}};
}
json evidence(const char *basis,json a,json aaaa) {
    return {{"schemaVersion",1},{"basis",basis},{"dns",{{"a",std::move(a)},{"aaaa",std::move(aaaa)}}}};
}
json failure(const char *status) {return {{"schemaVersion",2},{"status",status}};}
bool allowed(const std::set<std::string> &addresses,const ResolutionTarget &target) {
    for(const auto &item:addresses)if(!target.allowed_addresses.count(item))return false;
    return true;
}
std::set<std::string> hosts_addresses(const std::string &host) {
    std::ifstream file("/etc/hosts");
    if(!file)return {};
    std::set<std::string> addresses;
    std::string line;
    while(std::getline(file,line)) {
        line=line.substr(0,line.find('#'));
        std::istringstream row(line);std::string numeric,name;
        if(!(row>>numeric))continue;
        bool matches=false;
        while(row>>name) {
            try {if(EndpointSettings::normalize_host(name)==host)matches=true;}
            catch(...) {} // Other aliases do not change an exact valid match.
        }
        if(!matches)continue;
        // Invalid matching entries cannot provide positive corroboration.
        addresses.insert(canonical_readiness_address(numeric));
    }
    if(file.bad())return {};
    return addresses;
}
struct Resolver {
    struct __res_state state{};
    bool initialized=false;
    Resolver():initialized(res_ninit(&state)==0){}
    ~Resolver(){if(initialized)res_nclose(&state);}
    json query(const std::string &host,int type) {
        if(!initialized)return family("failed");
        // Public glibc resolver option, including runtimes newer than the 2.35
        // build headers: resolv.h defines RES_NOAAAA as 0x08000000.
        constexpr unsigned long no_aaaa=0x08000000;
        if(type==ns_t_aaaa && (state.options&no_aaaa))return family("failed");
        // DNS messages have a 16-bit wire length; no product quota is added.
        std::array<unsigned char,65535> bytes{};
        std::set<std::string> visited;auto current=host;
        while(visited.insert(current).second) {
            int size=res_nquery(&state,current.c_str(),ns_c_in,type,bytes.data(),bytes.size());
            if(size<0) {
                if(state.res_h_errno==HOST_NOT_FOUND || state.res_h_errno==NO_DATA)return family("absent");
                return family("failed");
            }
            try {
                auto answer=detail::parse_dns_answer(bytes.data(),static_cast<size_t>(size),type,current);
                if(!answer.addresses.empty())return family("answered",answer.addresses);
                if(!answer.alias)return family("absent");
                current=answer.terminal;
            } catch(...) {return family("failed");}
        }
        return family("failed");
    }
};
}
namespace detail {
DnsAnswer parse_dns_answer(const unsigned char *bytes,size_t size,int type,const std::string &host) {
    if(!bytes || size<NS_HFIXEDSZ || size>65535 || (type!=ns_t_a && type!=ns_t_aaaa))throw std::runtime_error("Invalid DNS message");
    ns_msg message{};
    if(ns_initparse(bytes,static_cast<int>(size),&message)<0 || !ns_msg_getflag(message,ns_f_qr) ||
       ns_msg_getflag(message,ns_f_opcode)!=ns_o_query || ns_msg_getflag(message,ns_f_tc) ||
       ns_msg_getflag(message,ns_f_rcode)!=ns_r_noerror || ns_msg_count(message,ns_s_qd)!=1)
        throw std::runtime_error("Invalid DNS response");
    ns_rr question{};
    if(ns_parserr(&message,ns_s_qd,0,&question)<0 || ns_rr_class(question)!=ns_c_in || ns_rr_type(question)!=type)
        throw std::runtime_error("Invalid DNS question");
    auto root=EndpointSettings::normalize_host(ns_rr_name(question));
    if(root!=EndpointSettings::normalize_host(host))throw std::runtime_error("Wrong DNS question name");
    std::map<std::string,std::string> aliases;
    std::vector<std::pair<std::string,std::string>> records;
    for(int index=0;index<ns_msg_count(message,ns_s_an);++index) {
        ns_rr row{};
        if(ns_parserr(&message,ns_s_an,index,&row)<0)throw std::runtime_error("Invalid DNS record");
        if(ns_rr_class(row)!=ns_c_in)throw std::runtime_error("Invalid DNS class");
        auto owner=EndpointSettings::normalize_host(ns_rr_name(row));
        if(ns_rr_type(row)==ns_t_cname) {
            std::array<char,NS_MAXDNAME> output{};
            int consumed=ns_name_uncompress(bytes,bytes+size,ns_rr_rdata(row),output.data(),output.size());
            if(consumed<0 || consumed!=ns_rr_rdlen(row))throw std::runtime_error("Invalid DNS alias");
            auto target=EndpointSettings::normalize_host(output.data());
            auto found=aliases.find(owner);
            if(found!=aliases.end() && found->second!=target)throw std::runtime_error("Conflicting DNS aliases");
            aliases[owner]=target;
        } else if(ns_rr_type(row)==ns_t_a || ns_rr_type(row)==ns_t_aaaa) {
            if(ns_rr_type(row)!=type || ns_rr_rdlen(row)!=(type==ns_t_a?4:16))
                throw std::runtime_error("Invalid DNS address record");
            records.emplace_back(owner,address(type==ns_t_a?AF_INET:AF_INET6,ns_rr_rdata(row),false));
        }
    }
    std::set<std::string> chain;auto terminal=root;
    while(true) {
        if(!chain.insert(terminal).second)throw std::runtime_error("DNS alias loop");
        auto found=aliases.find(terminal);if(found==aliases.end())break;
        terminal=found->second;
    }
    for(const auto &alias:aliases)if(!chain.count(alias.first))throw std::runtime_error("Unrelated DNS alias");
    std::set<std::string> addresses;
    for(const auto &[owner,numeric]:records) {
        if(owner!=terminal)throw std::runtime_error("Unrelated DNS address");
        addresses.insert(numeric);
    }
    return {std::move(addresses),terminal,!aliases.empty()};
}
}
json validate_resolution_evidence(const json &value) {
    fields(value,{"schemaVersion","basis","dns"});
    if(!value.at("schemaVersion").is_number_integer() || value.at("schemaVersion")!=1)
        throw std::runtime_error("Invalid resolution evidence version");
    auto basis=value.at("basis").get<std::string>();
    if(basis!="literal" && basis!="hosts" && basis!="system")throw std::runtime_error("Invalid resolution basis");
    fields(value.at("dns"),{"a","aaaa"});
    for(const auto *key:{"a","aaaa"}) {
        const auto &row=value.at("dns").at(key);fields(row,{"status","addresses"});
        auto status=row.at("status").get<std::string>();const auto &items=row.at("addresses");
        if(!items.is_array() || (status!="notChecked" && status!="answered" && status!="absent" && status!="failed") ||
           ((basis=="system")==(status=="notChecked")) || ((status=="answered")!=!items.empty()))
            throw std::runtime_error("Invalid DNS evidence state");
        std::set<std::string> seen;
        for(const auto &item:items) {
            auto numeric=item.get<std::string>();in_addr a{};in6_addr aaaa{};
            int valid=std::string(key)=="a"?inet_pton(AF_INET,numeric.c_str(),&a):inet_pton(AF_INET6,numeric.c_str(),&aaaa);
            if(valid!=1 || canonical_readiness_address(numeric)!=numeric || !seen.insert(numeric).second)
                throw std::runtime_error("Invalid DNS evidence address");
        }
    }
    return value;
}
bool complete_resolution_evidence(const json &value) {
    auto checked=validate_resolution_evidence(value);
    return checked.at("dns").at("a").at("status")!="failed" && checked.at("dns").at("aaaa").at("status")!="failed";
}
json resolve_readiness_dns(const ResolutionTarget &target) {
    std::set<std::string> selected;json proof;
    in_addr numeric4{};in6_addr numeric6{};
    if(inet_pton(AF_INET,target.host.c_str(),&numeric4)==1 || inet_pton(AF_INET6,target.host.c_str(),&numeric6)==1) {
        try {selected.insert(canonical_readiness_address(target.host));}
        catch(...) {return failure("dnsMismatch");}
        proof=evidence("literal",family("notChecked"),family("notChecked"));
    } else {
        addrinfo hints{};hints.ai_family=AF_UNSPEC;hints.ai_socktype=SOCK_STREAM;
        addrinfo *raw=nullptr;int error=getaddrinfo(target.host.c_str(),nullptr,&hints,&raw);
        std::unique_ptr<addrinfo,decltype(&freeaddrinfo)> answer(raw,freeaddrinfo);
        if(error)return failure("dnsFailed");
        try {
            for(auto *item=answer.get();item;item=item->ai_next) {
                if(item->ai_family==AF_INET && item->ai_addrlen>=sizeof(sockaddr_in))
                    selected.insert(address(AF_INET,&reinterpret_cast<sockaddr_in *>(item->ai_addr)->sin_addr));
                else if(item->ai_family==AF_INET6 && item->ai_addrlen>=sizeof(sockaddr_in6))
                    selected.insert(address(AF_INET6,&reinterpret_cast<sockaddr_in6 *>(item->ai_addr)->sin6_addr));
                else return failure("dnsFailed");
            }
        } catch(...) {return failure("dnsMismatch");}
        if(selected.empty())return failure("dnsFailed");
        if(!allowed(selected,target))return failure("dnsMismatch");
        std::set<std::string> hosts;
        try {hosts=hosts_addresses(target.host);}
        catch(...) {return failure("dnsMismatch");}
        if(!allowed(hosts,target))return failure("dnsMismatch");
        bool corroborated=false;
        try {corroborated=!hosts.empty() && std::includes(hosts.begin(),hosts.end(),selected.begin(),selected.end()) &&
            hosts==hosts_addresses(target.host);}
        catch(...) {return failure("dnsMismatch");}
        if(corroborated) {
            proof=evidence("hosts",family("notChecked"),family("notChecked"));
        } else {
            Resolver resolver;auto a=resolver.query(target.host,ns_t_a),aaaa=resolver.query(target.host,ns_t_aaaa);
            for(const auto &row:{a,aaaa}) {
                auto found=row.at("addresses").get<std::set<std::string>>();
                if(!allowed(found,target))return failure("dnsMismatch");
            }
            proof=evidence("system",std::move(a),std::move(aaaa));
        }
    }
    if(!allowed(selected,target))return failure("dnsMismatch");
    return {{"schemaVersion",2},{"status","resolved"},{"addresses",selected},
        {"resolution",validate_resolution_evidence(proof)}};
}
}
