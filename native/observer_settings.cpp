#include "observer_settings.hpp"
#include "endpoint_settings.hpp"
#include <cerrno>
#include <filesystem>
#include <fcntl.h>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>

namespace traverse {
namespace {
using json=nlohmann::json;
std::string text(const json &value,const char *key) {
    auto result=value.at(key).get<std::string>();
    if(result.find_first_of("\r\n")!=std::string::npos || result.find('\0')!=std::string::npos)
        throw std::runtime_error("Invalid observer setting");
    return result;
}
std::string path(const std::string &value,const std::string &directory,bool empty=false) {
    if(value.empty()) {
        if(empty)return {};
        throw std::runtime_error("Observer file path required");
    }
    auto p=std::filesystem::path(value);
    if(!p.is_absolute()) {
        if(directory.empty() || !std::filesystem::path(directory).is_absolute())
            throw std::runtime_error("Observer relative file requires configuration directory");
        p=std::filesystem::path(directory)/p;
    }
    return p.lexically_normal().string();
}
std::string read_private(const std::string &name,bool credential) {
    int descriptor=open(name.c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
    if(descriptor<0)throw std::runtime_error("Observer file unavailable");
    struct File {int fd;~File(){close(fd);}} file{descriptor};
    struct stat before{},after{},named{};
    if(fstat(descriptor,&before) || !S_ISREG(before.st_mode) ||
       (credential ? before.st_uid!=geteuid() || (before.st_mode&0077)
                   : (before.st_uid!=geteuid() && before.st_uid!=0) || (before.st_mode&0022)))
        throw std::runtime_error("Observer file permissions are unsafe");
    std::string bytes;char buffer[4096];
    while(true) {
        auto count=read(descriptor,buffer,sizeof(buffer));
        if(count<0 && errno==EINTR)continue;
        if(count<0)throw std::runtime_error("Observer file unreadable");
        if(!count)break;
        bytes.append(buffer,count);
    }
    if(fstat(descriptor,&after) || lstat(name.c_str(),&named) || !S_ISREG(named.st_mode) ||
       before.st_dev!=named.st_dev || before.st_ino!=named.st_ino ||
       before.st_size!=after.st_size || before.st_mtim.tv_sec!=after.st_mtim.tv_sec ||
       before.st_mtim.tv_nsec!=after.st_mtim.tv_nsec || before.st_ctim.tv_sec!=after.st_ctim.tv_sec ||
       before.st_ctim.tv_nsec!=after.st_ctim.tv_nsec)
        throw std::runtime_error("Observer file changed while being read");
    return bytes;
}
}
ObserverSettings ObserverSettings::parse(const json &value,const std::string &directory) {
    if(!value.is_object() || value.size()!=6)throw std::runtime_error("Invalid observer settings shape");
    for(auto key:{"host","port","caFile","registrationId","tokenFile","timeoutMs"})
        if(!value.contains(key))throw std::runtime_error("Incomplete observer settings");
    ObserverSettings result;
    result.host=EndpointSettings::normalize_host(text(value,"host"));
    const auto &port=value.at("port");
    if(!port.is_number_integer() || port<1 || port>65535)throw std::runtime_error("Invalid observer port");
    result.port=port.get<std::uint16_t>();result.ca_file=path(text(value,"caFile"),directory,true);
    result.token_file=path(text(value,"tokenFile"),directory);
    result.registration_id=text(value,"registrationId");
    if(result.registration_id.size()!=32 || result.registration_id.find_first_not_of("0123456789abcdef")!=std::string::npos)
        throw std::runtime_error("Invalid observer registration ID");
    const auto &timeout=value.at("timeoutMs");
    if(!timeout.is_null()) {
        if(!timeout.is_number_integer() || timeout<1 || timeout>INT64_MAX)throw std::runtime_error("Invalid observer timeout");
        result.timeout_ms=timeout.get<std::int64_t>();
    }
    return result;
}
nlohmann::json ObserverSettings::agent_configuration() const {
    return {{"host",host},{"port",port},{"caFile",ca_file},{"registrationId",registration_id},{"tokenFile",token_file},
        {"timeoutMs",timeout_ms?json(*timeout_ms):json(nullptr)}};
}
nlohmann::json secure_observer_configuration(const std::string &name) {
    auto result=json::parse(read_private(name,false));
    if(!result.is_object() || !result.contains("observerSettings"))throw std::runtime_error("Observer configuration changed");
    return result;
}
std::string read_observer_ca(const std::string &name) { return read_private(name,false); }
std::string read_observer_credential(const std::string &name) {
    auto value=read_private(name,true);
    if(!value.empty() && value.back()=='\n') {
        value.pop_back();if(!value.empty() && value.back()=='\r')value.pop_back();
    }
    if(value.size()!=64 || value.find_first_not_of("0123456789abcdef")!=std::string::npos)
        throw std::runtime_error("Invalid observer credential file");
    return value;
}
}
