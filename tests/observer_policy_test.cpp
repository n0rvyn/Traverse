#include "observer_policy.hpp"
#include <functional>
#include <iostream>
#include <arpa/nameser.h>
using nlohmann::json;
void require(bool ok,const char *message){if(!ok)throw std::runtime_error(message);}
void rejected(const std::function<void()> &fn){bool bad=false;try{fn();}catch(...){bad=true;}require(bad,"Invalid observer policy accepted");}
using Bytes=std::vector<unsigned char>;
void word(Bytes &out,unsigned value){out.push_back(value>>8);out.push_back(value&255);}
Bytes name(const std::string &value){Bytes out;size_t start=0;while(start<value.size()){
    auto end=value.find('.',start);if(end==std::string::npos)end=value.size();out.push_back(end-start);
    out.insert(out.end(),value.begin()+start,value.begin()+end);start=end+1;}out.push_back(0);return out;}
struct Record{std::string owner;unsigned type;Bytes data;};
Bytes packet(const std::vector<Record> &records,unsigned flags=0x8180){
    Bytes out;word(out,1);word(out,flags);word(out,1);word(out,records.size());word(out,0);word(out,0);
    auto question=name("target.example.test");out.insert(out.end(),question.begin(),question.end());word(out,ns_t_a);word(out,ns_c_in);
    for(const auto &record:records){auto owner=name(record.owner);out.insert(out.end(),owner.begin(),owner.end());
        word(out,record.type);word(out,ns_c_in);word(out,0);word(out,1);word(out,record.data.size());out.insert(out.end(),record.data.begin(),record.data.end());}
    return out;
}
auto parse(const Bytes &bytes){return traverse::detail::parse_dns_answer(bytes.data(),bytes.size(),ns_t_a,"target.example.test");}
int main(){try{
    auto plain=packet({{"target.example.test",ns_t_a,{127,0,0,1}}});
    require(parse(plain).addresses==std::set<std::string>{"127.0.0.1"},"Real DNS record parsing failed");
    auto cname=packet({{"target.example.test",ns_t_cname,name("alias.example.test")},{"alias.example.test",ns_t_a,{127,0,0,1}}});
    require(parse(cname).addresses==std::set<std::string>{"127.0.0.1"},"CNAME target lost");
    auto pending=parse(packet({{"target.example.test",ns_t_cname,name("alias.example.test")}}));
    require(pending.alias && pending.addresses.empty() && pending.terminal=="alias.example.test","CNAME continuation lost");
    require(parse(packet({})).addresses.empty(),"Empty DNS answer became data");
    for(auto flags:{0x8182u,0x8380u,0x0180u})rejected([&]{parse(packet({{"target.example.test",ns_t_a,{127,0,0,1}}},flags));});
    rejected([&]{parse(packet({{"foreign.example.test",ns_t_a,{127,0,0,1}}}));});
    rejected([&]{parse(packet({{"target.example.test",ns_t_a,{127,0,0}}}));});
    rejected([&]{parse(packet({{"target.example.test",ns_t_cname,{0xc0,0xff}}}));});
    rejected([&]{parse(packet({{"target.example.test",ns_t_cname,name("alias.example.test")},{"alias.example.test",ns_t_cname,name("target.example.test")}}));});
    rejected([&]{parse(packet({{"target.example.test",ns_t_cname,name("a.example.test")},{"target.example.test",ns_t_cname,name("b.example.test")}}));});
    rejected([&]{traverse::detail::parse_dns_answer(plain.data(),plain.size(),ns_t_a,"different.example.test");});
    for(size_t end=0;end<plain.size();++end)rejected([&]{parse(Bytes(plain.begin(),plain.begin()+end));});
    json proof={{"schemaVersion",1},{"basis","system"},{"dns",{{"a",{{"status","answered"},{"addresses",{"127.0.0.1"}}}},
        {"aaaa",{{"status","failed"},{"addresses",json::array()}}}}}};
    require(!traverse::complete_resolution_evidence(proof),"Partial DNS failure became complete");
    auto good=proof;good["dns"]["aaaa"]["status"]="absent";require(traverse::complete_resolution_evidence(good),"Ordinary absent family failed");
    for(auto key:{"a","aaaa"}){auto bad=proof;bad["dns"][key]["extra"]=true;rejected([&]{traverse::validate_resolution_evidence(bad);});}
    auto badProof=proof;badProof["basis"]="hosts";rejected([&]{traverse::validate_resolution_evidence(badProof);});
    badProof=proof;badProof["dns"]["a"]["addresses"]={"::1"};rejected([&]{traverse::validate_resolution_evidence(badProof);});
    badProof=proof;badProof["dns"]["a"]["addresses"]={"127.0.0.1","127.0.0.1"};rejected([&]{traverse::validate_resolution_evidence(badProof);});
    badProof=proof;badProof["dns"]["a"]["addresses"]=json::array();rejected([&]{traverse::validate_resolution_evidence(badProof);});
    json row={{"id",std::string(32,'a')},{"token",std::string(64,'b')},{"target",{
        {"host","TARGET.example.test"},{"port",8443},{"basePath","/traverse/v1.2/"},{"caFile",""},
        {"allowedAddresses",{"127.0.0.1","::1"}}}}};
    json config={{"schemaVersion",1},{"listenAddress","127.0.0.1"},{"port",9443},
        {"certificate","/private/cert.pem"},{"privateKey","/private/key.pem"},{"registrations",json::array({row})}};
    auto registry=traverse::ObserverConfiguration::parse(config);auto reg=registry.registrations.begin()->second;
    require(reg.target.host=="target.example.test" && reg.target.origin=="https://target.example.test:8443","Target canonicalization drift");
    auto resolution=traverse::parse_resolution_request(reg.resolution_request());
    require(resolution.allowed_addresses.size()==2,"Address policy lost");
    auto bad=config;auto duplicate=row;duplicate["token"]=std::string(64,'c');bad["registrations"].push_back(duplicate);
    rejected([&]{traverse::ObserverConfiguration::parse(bad);});
    bad=config;duplicate=row;duplicate["id"]=std::string(32,'c');bad["registrations"].push_back(duplicate);
    rejected([&]{traverse::ObserverConfiguration::parse(bad);});
    for(auto addresses:std::vector<json>{json::array(),json::array({"127.0.0.1","127.0.0.1"}),json::array({"localhost"}),json::array({"0.0.0.0"})}){
        bad=config;bad["registrations"][0]["target"]["allowedAddresses"]=addresses;rejected([&]{traverse::ObserverConfiguration::parse(bad);});
    }
    for(auto port:std::vector<json>{0,65536,9443.0,true}){bad=config;bad["port"]=port;rejected([&]{traverse::ObserverConfiguration::parse(bad);});}
    bad=config;bad["extra"]=true;rejected([&]{traverse::ObserverConfiguration::parse(bad);});
    json lease={{"instance",std::string(32,'c')},{"id",std::string(32,'d')},{"token",std::string(64,'e')},{"nonce",std::string(64,'f')}};
    auto request=reg.verification("::1",lease);
    require(traverse::parse_readiness_verification(request).target.address=="::1","Registered pin lost");
    rejected([&]{reg.verification("192.0.2.1",lease);});
    lease["controller"]=true;rejected([&]{reg.verification("::1",lease);});
    auto literal=resolution;literal.host="127.0.0.1";
    require(traverse::resolve_readiness_dns(literal).at("status")=="resolved","Explicit literal grant failed");
    literal.allowed_addresses={"::1"};auto denied=traverse::resolve_readiness_dns(literal);
    require(denied.at("status")=="dnsMismatch" && !denied.contains("addresses"),"Unapproved literal disclosed or accepted");
    auto invalid=reg.resolution_request();invalid["schemaVersion"]=2.0;rejected([&]{traverse::parse_resolution_request(invalid);});
    std::cout<<"Observer immutable policy, duplicate authority, target and address contracts passed\n";return 0;
}catch(const std::exception &error){std::cerr<<error.what()<<'\n';return 1;}}
