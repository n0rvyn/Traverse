#include "readiness_media.hpp"
#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <iostream>
#include <poll.h>
#include <unistd.h>
int main(int argc,char **argv) {
    std::signal(SIGPIPE,SIG_IGN);
    try {
        if(argc!=2 && argc!=3)return 2;
        traverse::ReadinessMedia owner(argv[1],argc==3?argv[2]:"");
        int flags=fcntl(STDIN_FILENO,F_GETFL);
        if(flags<0 || fcntl(STDIN_FILENO,F_SETFL,flags|O_NONBLOCK))return 2;
        std::string pending;
        bool stopped=false;
        while(!stopped) {
            for(auto &event:owner.events())std::cout<<event.dump()<<std::endl;
            pollfd input{STDIN_FILENO,POLLIN,0};
            if(poll(&input,1,5)<0){if(errno==EINTR)continue;return 2;}
            if(!(input.revents&(POLLIN|POLLHUP|POLLERR)))continue;
            char bytes[4096];auto count=read(STDIN_FILENO,bytes,sizeof(bytes));
            if(!count)break;
            if(count<0){if(errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR)continue;return 2;}
            pending.append(bytes,count);
            for(std::size_t end;(end=pending.find('\n'))!=std::string::npos;) {
                auto text=pending.substr(0,end);pending.erase(0,end+1);
                auto value=nlohmann::json::parse(text);auto op=value.at("op").get<std::string>();
                bool ok=true;
                if(op=="begin")ok=owner.begin(value.at("config").at("peer"),value.at("config"));
                else if(op=="relay") {
                    const auto &grant=value.at("grant");
                    ok=owner.prepare_relay(value.at("id"),{grant.at("addresses").get<std::vector<std::string>>(),
                        grant.at("port").get<std::uint16_t>(),grant.at("username"),grant.at("credential"),grant.value("route",std::string{})});
                }
                else if(op=="allocations") {
                    auto sockets=owner.relay_allocations(value.at("id"));auto peers=nlohmann::json::array();
                    if(sockets)for(const auto &peer:*sockets)peers.push_back({{"address",peer.address},{"port",peer.port}});
                    std::cout<<nlohmann::json({{"reply",op},{"ok",sockets.has_value()},{"peers",peers}}).dump()<<std::endl;continue;
                }
                else if(op=="command")ok=owner.command(value.at("id"),value.at("command"));
                else if(op=="end")owner.end(value.at("id"));
                else if(op=="preempt")owner.preempt();
                else if(op=="release")owner.owner_revoked_controller();
                else if(op=="stop"){owner.stop();stopped=true;}
                else return 2;
                std::cout<<nlohmann::json({{"reply",op},{"ok",ok},{"idle",owner.idle()}}).dump()<<std::endl;
            }
        }
        owner.stop();return 0;
    } catch(const std::exception &error){std::cerr<<error.what()<<std::endl;return 1;}
}
