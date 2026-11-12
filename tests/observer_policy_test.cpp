#include "observer_policy.hpp"
#include <functional>
#include <iostream>
using nlohmann::json;
void require(bool ok,const char *message){if(!ok)throw std::runtime_error(message);}
void rejected(const std::function<void()> &fn){bool bad=false;try{fn();}catch(...){bad=true;}require(bad,"Invalid observer policy accepted");}
int main(){try{
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
