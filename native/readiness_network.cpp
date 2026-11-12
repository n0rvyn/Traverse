#include "readiness_network.hpp"
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <functional>
#include <limits>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <map>
#include <set>
#include <stdexcept>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

namespace traverse {
struct ReadinessNetwork::State {
    int route=-1,notify=-1;
    bool healthy=true;
    std::vector<std::string> files;
    struct Watch {bool self=false;std::set<std::string> names;};
    std::map<int,Watch> watches;
    explicit State(std::vector<std::string> values):files(std::move(values)) {
        route=socket(AF_NETLINK,SOCK_RAW|SOCK_CLOEXEC|SOCK_NONBLOCK,NETLINK_ROUTE);
        sockaddr_nl address{};address.nl_family=AF_NETLINK;
        address.nl_groups=RTMGRP_LINK|RTMGRP_IPV4_IFADDR|RTMGRP_IPV6_IFADDR|RTMGRP_IPV4_ROUTE|RTMGRP_IPV6_ROUTE;
        if(route<0 || bind(route,reinterpret_cast<sockaddr*>(&address),sizeof(address)))healthy=false;
        try {if(!rebuild())healthy=false;}catch(...){healthy=false;}
    }
    ~State(){if(route>=0)close(route);if(notify>=0)close(notify);}
    bool rebuild() {
        int replacement=inotify_init1(IN_CLOEXEC|IN_NONBLOCK);
        if(replacement<0)return false;
        std::map<int,Watch> next;
        bool valid=true;std::set<std::string> visited;
        constexpr auto mask=IN_MODIFY|IN_CLOSE_WRITE|IN_ATTRIB|IN_CREATE|IN_DELETE|IN_MOVED_FROM|IN_MOVED_TO|IN_MOVE_SELF|IN_DELETE_SELF|IN_UNMOUNT;
        auto add=[&](const std::filesystem::path &path,const std::string &child) {
            int wd=inotify_add_watch(replacement,path.c_str(),mask);
            if(wd<0){if(errno!=ENOENT && errno!=ENOTDIR)valid=false;return;}
            if(child.empty())next[wd].self=true;else next[wd].names.insert(child);
        };
        std::function<void(std::filesystem::path)> walk=[&](std::filesystem::path path) {
            path=path.lexically_normal();
            if(!path.is_absolute()){valid=false;return;}
            if(!visited.insert(path.string()).second)return;
            std::filesystem::path prefix="/";
            for(const auto &part:path.relative_path()) {
                add(prefix,part.string());prefix/=part;
                std::error_code error;auto status=std::filesystem::symlink_status(prefix,error);
                if(error) {
                    if(error!=std::errc::no_such_file_or_directory && error!=std::errc::not_a_directory)valid=false;
                    break;
                }
                if(std::filesystem::is_symlink(status)) {
                    auto target=std::filesystem::read_symlink(prefix,error);
                    if(error){valid=false;break;}
                    walk(target.is_absolute()?target:prefix.parent_path()/target);
                }
            }
            add(path,"");
        };
        try {for(const auto &file:files)walk(file);}catch(...){close(replacement);throw;}
        if(!valid){close(replacement);return false;}
        if(notify>=0)close(notify);
        notify=replacement;watches=std::move(next);return true;
    }
    bool route_changed() {
        if(route<0)return false;
        char byte; iovec preview{&byte,1};sockaddr_nl sender{};
        msghdr peek{};peek.msg_name=&sender;peek.msg_namelen=sizeof(sender);peek.msg_iov=&preview;peek.msg_iovlen=1;
        auto size=recvmsg(route,&peek,MSG_PEEK|MSG_TRUNC|MSG_DONTWAIT);
        if(size<0) {
            if(errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR)return false;
            healthy=false;close(route);route=-1;return true;
        }
        if(size==0 || size>std::numeric_limits<int>::max()){healthy=false;close(route);route=-1;return true;}
        std::vector<char> bytes(static_cast<size_t>(size));iovec body{bytes.data(),bytes.size()};
        msghdr message{};message.msg_name=&sender;message.msg_namelen=sizeof(sender);message.msg_iov=&body;message.msg_iovlen=1;
        auto count=recvmsg(route,&message,MSG_DONTWAIT);
        if(count<0) {
            if(errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR)return false;
            healthy=false;close(route);route=-1;return true;
        }
        if(message.msg_namelen!=sizeof(sender) || sender.nl_family!=AF_NETLINK || sender.nl_pid!=0)return false;
        if(message.msg_flags&MSG_TRUNC){healthy=false;return true;}
        int remaining=static_cast<int>(count);bool changed=false;
        for(auto *header=reinterpret_cast<nlmsghdr*>(bytes.data());NLMSG_OK(header,remaining);header=NLMSG_NEXT(header,remaining)) {
            switch(header->nlmsg_type) {
                case RTM_NEWLINK:case RTM_DELLINK:case RTM_NEWADDR:case RTM_DELADDR:case RTM_NEWROUTE:case RTM_DELROUTE:changed=true;break;
                case NLMSG_ERROR:case NLMSG_OVERRUN:healthy=false;changed=true;break;
                default:break;
            }
        }
        if(remaining){healthy=false;changed=true;}
        return changed;
    }
    bool files_changed() {
        if(notify<0)return false;
        int available=0;
        if(ioctl(notify,FIONREAD,&available) || available<0){healthy=false;close(notify);notify=-1;return true;}
        if(!available)return false;
        std::vector<char> bytes(static_cast<size_t>(available));auto count=read(notify,bytes.data(),bytes.size());
        if(count<0) {
            if(errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR)return false;
            healthy=false;close(notify);notify=-1;return true;
        }
        bool changed=false;size_t offset=0;
        while(offset<static_cast<size_t>(count)) {
            if(static_cast<size_t>(count)-offset<sizeof(inotify_event)){healthy=false;changed=true;break;}
            auto *event=reinterpret_cast<const inotify_event*>(bytes.data()+offset);
            if(event->len>static_cast<size_t>(count)-offset-sizeof(inotify_event)){healthy=false;changed=true;break;}
            if(event->mask&(IN_Q_OVERFLOW|IN_UNMOUNT)){healthy=false;changed=true;}
            if(event->mask&IN_IGNORED)changed=true;
            auto found=watches.find(event->wd);
            if(found!=watches.end()) {
                if(!event->len && found->second.self)changed=true;
                else if(event->len) {
                    const auto *end=static_cast<const char*>(memchr(event->name,0,event->len));
                    if(!end){healthy=false;changed=true;}
                    else if(found->second.names.count(std::string(event->name,end)))changed=true;
                }
            }
            offset+=sizeof(inotify_event)+event->len;
        }
        if(changed && !rebuild())healthy=false;
        return changed;
    }
};
ReadinessNetwork::ReadinessNetwork(std::vector<std::string> files):state(std::make_unique<State>(std::move(files))){}
ReadinessNetwork::~ReadinessNetwork()=default;
ReadinessNetwork::Observation ReadinessNetwork::poll() {
    try {
        bool changed=state->route_changed();changed=state->files_changed() || changed;
        return {changed,state->healthy};
    }catch(...) {
        state->healthy=false;
        if(state->route>=0){close(state->route);state->route=-1;}
        if(state->notify>=0){close(state->notify);state->notify=-1;}
        return {true,false};
    }
}
}
