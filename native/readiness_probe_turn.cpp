#include "readiness_probe_turn.hpp"
#include <arpa/inet.h>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <linux/capability.h>
#include <linux/memfd.h>
#include <set>
#include <sstream>
#include <stdexcept>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

namespace traverse {
namespace {
struct Descriptor {
    int fd;
    explicit Descriptor(int value=-1):fd(value) {}
    ~Descriptor(){if(fd>=0)close(fd);}
    Descriptor(const Descriptor &)=delete;
};
int private_descriptor(int original) {
    if(original<0)return -1;
    int descriptor=fcntl(original,F_DUPFD_CLOEXEC,3);close(original);return descriptor;
}
void require(bool condition) {
    if(!condition)throw std::runtime_error("Private probe relay unavailable");
}
bool secret(const std::string &text) {
    return text.size()==64 && text.find_first_not_of("0123456789abcdef")==std::string::npos;
}
std::string numeric_address(const std::string &text) {
    unsigned char bytes[16];char canonical[INET6_ADDRSTRLEN];
    int family=text.find(':')==std::string::npos?AF_INET:AF_INET6;
    require(inet_pton(family,text.c_str(),bytes)==1);
    require(inet_ntop(family,bytes,canonical,sizeof(canonical))!=nullptr);
    return canonical;
}
std::vector<std::string> words(const std::string &line) {
    std::istringstream stream(line);std::vector<std::string> result;std::string word;
    while(stream>>word)result.push_back(word);
    return result;
}
ReadinessMediaPeer endpoint(const std::string &text,bool ipv6) {
    auto separator=text.find(':');require(separator==(ipv6?32u:8u));
    auto hex=text.substr(0,separator);unsigned char bytes[16]{};
    // Linux procfs prints each network address as native-endian uint32 words.
    for(std::size_t offset=0;offset<hex.size();offset+=8) {
        auto word=static_cast<std::uint32_t>(std::stoul(hex.substr(offset,8),nullptr,16));
        std::memcpy(bytes+offset/2,&word,sizeof(word));
    }
    char address[INET6_ADDRSTRLEN];
    require(inet_ntop(ipv6?AF_INET6:AF_INET,bytes,address,sizeof(address))!=nullptr);
    auto port=std::stoul(text.substr(separator+1),nullptr,16);require(port && port<=65535);
    return {address,static_cast<std::uint16_t>(port)};
}
}
struct ReadinessProbeTurn::State {
    pid_t pid=-1;
    std::uint16_t backend=0;
    explicit State(const std::filesystem::path &binary,const std::vector<std::string> &addresses,
                   std::uint16_t peer_port,const std::string &user,const std::string &password) {
        require(binary.is_absolute() && geteuid()!=0 && peer_port && !addresses.empty() && secret(user) && secret(password));
        Descriptor reservation(socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0));
        sockaddr_in local{};local.sin_family=AF_INET;local.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        require(reservation.fd>=0 && !bind(reservation.fd,reinterpret_cast<sockaddr *>(&local),sizeof(local)));
        socklen_t length=sizeof(local);require(!getsockname(reservation.fd,reinterpret_cast<sockaddr *>(&local),&length));
        backend=ntohs(local.sin_port);
        std::string config="listening-ip=127.0.0.1\nlistening-port="+std::to_string(backend)+
            "\nno-udp\nno-tls\ndtls=false\ncli=false\nweb-admin=false\nno-tcp-relay\nno-stun\n"
            "lt-cred-mech\nrealm=traverse-probe\nuser="+user+":"+password+
            "\ndenied-peer-ip=0.0.0.0-255.255.255.255\n"
            "denied-peer-ip=::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff\n"
            "no-multicast-peers\nprobe-peer-port="+std::to_string(peer_port)+
            "\nrelay-threads=1\npidfile=/dev/null\nuserdb=/dev/null\nlog-file=stdout\nsimple-log\n";
        std::set<std::string> frozen;
        for(const auto &address:addresses)frozen.insert(numeric_address(address));
        for(const auto &address:frozen) {
            config+="relay-ip="+address+"\nallowed-peer-ip="+address+"\n";
            if(address=="127.0.0.1" || address=="::1")config+="allow-loopback-peers\n";
        }
        Descriptor settings(private_descriptor(static_cast<int>(syscall(SYS_memfd_create,"traverse-probe",MFD_CLOEXEC|MFD_ALLOW_SEALING))));
        require(settings.fd>=0 && !fchmod(settings.fd,0600));
        std::size_t sent=0;
        while(sent<config.size()) {
            auto count=write(settings.fd,config.data()+sent,config.size()-sent);
            if(count<0 && errno==EINTR)continue;
            require(count>0);sent+=static_cast<std::size_t>(count);
        }
        require(lseek(settings.fd,0,SEEK_SET)==0 && !fcntl(settings.fd,F_ADD_SEALS,F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL));
        Descriptor null(private_descriptor(open("/dev/null",O_RDWR|O_CLOEXEC)));require(null.fd>=0);
        auto executable=binary.string();char option[]="-c",path[]="/proc/self/fd/0";
        char *arguments[]={executable.data(),option,path,nullptr};
        std::string library;
        if(const char *value=getenv("LD_LIBRARY_PATH"))library="LD_LIBRARY_PATH="+std::string(value);
        char *environment[]={library.empty()?nullptr:library.data(),nullptr};
        const auto parent=getpid();
        // The reserved port is no longer a promise after close: readiness below
        // requires a listening socket owned by this exact child before routing.
        close(reservation.fd);reservation.fd=-1;
        pid=fork();require(pid>=0);
        if(!pid) {
            // No allocating/locking libc operations after fork in the service.
            __user_cap_header_struct header{_LINUX_CAPABILITY_VERSION_3,0};
            __user_cap_data_struct capabilities[2]{};
            if(prctl(PR_SET_PDEATHSIG,SIGKILL) || getppid()!=parent ||
               syscall(SYS_capset,&header,capabilities) ||
               prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_CLEAR_ALL,0,0,0) ||
               prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0) ||
               dup2(settings.fd,STDIN_FILENO)<0 || dup2(null.fd,STDOUT_FILENO)<0 ||
               dup2(null.fd,STDERR_FILENO)<0 || syscall(SYS_close_range,3u,~0u,0u))_exit(126);
            execve(executable.c_str(),arguments,environment);_exit(127);
        }
    }
    ~State(){stop();}
    void check() {
        require(pid>0);int status=0;auto result=waitpid(pid,&status,WNOHANG);
        if(result==pid){pid=-1;require(false);}
        if(result<0 && errno==ECHILD){pid=-1;require(false);}
        require(result==0 || (result<0 && errno==EINTR));
    }
    struct Socket {std::string protocol,local;};
    std::vector<Socket> sockets() {
        check();auto process=std::filesystem::path("/proc")/std::to_string(pid);
        std::set<std::string> inodes;
        for(const auto &entry:std::filesystem::directory_iterator(process/"fd")) {
            std::error_code error;auto link=std::filesystem::read_symlink(entry.path(),error).string();
            if(error){require(error.value()==ENOENT);continue;}
            if(link.rfind("socket:[",0)==0 && link.back()==']')inodes.insert(link.substr(8,link.size()-9));
        }
        std::vector<Socket> result;
        for(const auto *protocol:{"tcp","tcp6","udp","udp6"}) {
            std::ifstream table(process/"net"/protocol);require(table.good());std::string line;
            std::getline(table,line);
            while(std::getline(table,line)) {
                auto row=words(line);require(row.size()>=10);
                if(inodes.count(row[9]) && (std::string(protocol).rfind("udp",0)==0 || row[3]=="0A"))
                    result.push_back({protocol,row[1]});
            }
        }
        check();return result;
    }
    void stop() noexcept {
        if(pid<=0)return;
        pid_t result;
        do {result=waitpid(pid,nullptr,WNOHANG);}while(result<0 && errno==EINTR);
        if(result!=0){pid=-1;return;}
        kill(pid,SIGKILL);
        while(waitpid(pid,nullptr,0)<0 && errno==EINTR){}
        pid=-1;
    }
};
ReadinessProbeTurn::ReadinessProbeTurn(const std::filesystem::path &binary,const std::vector<std::string> &addresses,
    std::uint16_t port,const std::string &user,const std::string &password)
    :state(std::make_unique<State>(binary,addresses,port,user,password)) {}
ReadinessProbeTurn::~ReadinessProbeTurn()=default;
bool ReadinessProbeTurn::ready() {
    for(const auto &socket:state->sockets())if(socket.protocol=="tcp") {
        auto peer=endpoint(socket.local,false);
        if(peer.address=="127.0.0.1" && peer.port==state->backend)return true;
    }
    return false;
}
std::uint16_t ReadinessProbeTurn::port() const{return state->backend;}
std::vector<ReadinessMediaPeer> ReadinessProbeTurn::allocations() {
    std::vector<ReadinessMediaPeer> result;
    for(const auto &socket:state->sockets())if(socket.protocol.rfind("udp",0)==0)
        result.push_back(endpoint(socket.local,socket.protocol=="udp6"));
    return result;
}
void ReadinessProbeTurn::stop(){state->stop();}
}
