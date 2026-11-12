#include "observer_settings.hpp"
#include "endpoint_settings.hpp"
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <sys/stat.h>
#include <unistd.h>
using nlohmann::json;
namespace {
std::function<void()> after_read;
ino_t watched_inode=0;
}
extern "C" ssize_t __real_read(int,void *,size_t);
extern "C" ssize_t __wrap_read(int fd,void *buffer,size_t size) {
    auto result=__real_read(fd,buffer,size);
    struct stat item{};
    if(result>0 && after_read && !fstat(fd,&item) && item.st_ino==watched_inode) {
        auto action=std::move(after_read);after_read={};action();
    }
    return result;
}
void require(bool value,const char *message){if(!value)throw std::runtime_error(message);}
void rejects(const std::function<void()> &operation){bool failed=false;try{operation();}catch(...){failed=true;}require(failed,"Unsafe observer settings accepted");}
int main(){try{
    auto root=std::filesystem::temp_directory_path()/(std::string("observer-settings-")+std::to_string(getpid()));
    require(std::filesystem::create_directory(root),"Cannot create settings fixture");chmod(root.c_str(),0700);
    struct Cleanup{std::filesystem::path path;~Cleanup(){std::error_code error;std::filesystem::remove_all(path,error);}} cleanup{root};
    json value={{"host","Observer.EXAMPLE.test"},{"port",443},{"caFile","root.pem"},
        {"registrationId",std::string(32,'a')},{"tokenFile","registration.key"},{"timeoutMs",1000}};
    auto parsed=traverse::ObserverSettings::parse(value,root.string());
    require(parsed.host=="observer.example.test" && parsed.token_file==(root/"registration.key").string() && parsed.timeout_ms==1000,"Observer metadata did not normalize");
    auto round=traverse::ObserverSettings::parse(parsed.agent_configuration(),"");require(round.token_file==parsed.token_file,"Observer metadata roundtrip changed");
    auto bad=value;bad["token"]="secret";rejects([&]{traverse::ObserverSettings::parse(bad,root.string());});
    bad=value;bad.erase("timeoutMs");rejects([&]{traverse::ObserverSettings::parse(bad,root.string());});
    for(auto timeout:std::vector<json>{0,-1,1.0,true,UINT64_MAX}){bad=value;bad["timeoutMs"]=timeout;rejects([&]{traverse::ObserverSettings::parse(bad,root.string());});}
    value["timeoutMs"]=nullptr;require(!traverse::ObserverSettings::parse(value,root.string()).timeout_ms,"Explicit no-deadline changed");
    auto token=root/"registration.key";{std::ofstream out(token);out<<std::string(64,'b')<<'\n';}chmod(token.c_str(),0600);
    require(traverse::read_observer_credential(token.string())==std::string(64,'b'),"Private credential read failed");
    chmod(token.c_str(),0644);rejects([&]{traverse::read_observer_credential(token.string());});chmod(token.c_str(),0600);
    auto link=root/"token-link";std::filesystem::create_symlink(token,link);rejects([&]{traverse::read_observer_credential(link.string());});
    {std::ofstream out(token);out<<std::string(64,'b')<<"\n\n";}rejects([&]{traverse::read_observer_credential(token.string());});
    auto config=root/"config.json";json document={{"schemaVersion",1},{"observerSettings",value}};
    {std::ofstream out(config);out<<document.dump();}chmod(config.c_str(),0644);
    require(traverse::secure_observer_configuration(config.string())==document,"Read-only public metadata rejected");
    chmod(config.c_str(),0666);rejects([&]{traverse::secure_observer_configuration(config.string());});chmod(config.c_str(),0600);
    auto config_link=root/"config-link";std::filesystem::create_symlink(config,config_link);rejects([&]{traverse::secure_observer_configuration(config_link.string());});
    struct stat watched{};require(!stat(config.c_str(),&watched),"Cannot inspect fixture");watched_inode=watched.st_ino;
    after_read=[&]{std::ofstream out(config,std::ios::app);out<<' ';};
    rejects([&]{traverse::secure_observer_configuration(config.string());});
    require(!after_read,"Changed-FD fixture did not execute");
    auto replacement=root/"replacement.json";{std::ofstream out(replacement);out<<document.dump();}chmod(replacement.c_str(),0600);
    after_read=[&]{std::filesystem::rename(replacement,config);};
    rejects([&]{traverse::secure_observer_configuration(config.string());});
    require(!after_read,"Named replacement fixture did not execute");
    auto ca=root/"root.pem";{std::ofstream out(ca);out<<"synthetic CA bytes";}chmod(ca.c_str(),0644);
    require(traverse::read_observer_ca(ca.string())=="synthetic CA bytes","Trusted public CA file read failed");
    chmod(ca.c_str(),0666);rejects([&]{traverse::read_observer_ca(ca.string());});
    std::cout<<"Observer metadata, private credential and same-FD configuration/CA guards passed\n";return 0;
}catch(const std::exception &error){std::cerr<<error.what()<<'\n';return 1;}}
