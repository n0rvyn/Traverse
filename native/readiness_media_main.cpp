#include "readiness_media_transport.hpp"
#include "bind_privilege.hpp"
#include <gst/gst.h>
#include <charconv>
#include <cerrno>
#include <csignal>
#include <deque>
#include <fcntl.h>
#include <iostream>
#include <poll.h>
#include <sys/prctl.h>
#include <unistd.h>
namespace {
volatile std::sig_atomic_t stopping=0;
void stop(int){stopping=1;}
void nonblocking(int fd){int flags=fcntl(fd,F_GETFL);if(flags<0 || fcntl(fd,F_SETFL,flags|O_NONBLOCK)<0)throw std::runtime_error("Private worker channel unavailable");}
struct Output {
    std::deque<std::string> records;
    std::size_t offset=0;
    void add(const nlohmann::json &value){records.push_back(value.dump()+'\n');}
    bool flush(){
        while(!records.empty()) {
            const auto &record=records.front();auto count=write(STDOUT_FILENO,record.data()+offset,record.size()-offset);
            if(count>0){offset+=count;if(offset==record.size()){offset=0;records.pop_front();}}
            else if(count<0 && (errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR))return true;
            else return false;
        }
        return true;
    }
};
}
int main(int argc,char **argv) {
    using json=nlohmann::json;
    std::signal(SIGPIPE,SIG_IGN);std::signal(SIGTERM,stop);std::signal(SIGINT,stop);
    try {
        // High-port launches do not pass through the binding helper. Prevent
        // acquiring new privilege on exec in either launch path, retaining the
        // existing binding capability only when inherited for a fixed low port.
        if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0))return 2;
        if(argc!=1) {
            if(argc!=3 || std::string(argv[1])!="--supervisor-pid")return 2;
            pid_t parent=-1;auto end=argv[2]+std::char_traits<char>::length(argv[2]);auto parsed=std::from_chars(argv[2],end,parent);
            if(parsed.ec!=std::errc{} || parsed.ptr!=end || parent<=1 || prctl(PR_SET_PDEATHSIG,SIGTERM) || getppid()!=parent)return 2;
        }
        nonblocking(STDIN_FILENO);nonblocking(STDOUT_FILENO);
        std::unique_ptr<traverse::ReadinessMediaTransport> transport;
        std::optional<traverse::ReadinessMediaConfig> config;
        Output output;std::string pending;bool owner_gone=false,requested_stop=false;
        while(!stopping && !owner_gone && !requested_stop) {
            // Keep private Stop/input servicing fair even while GLib sources
            // remain continuously ready.
            g_main_context_iteration(nullptr,FALSE);
            if(transport){transport->tick();for(auto &event:transport->events())output.add(event);if(transport->failed())break;}
            if(!output.flush()){owner_gone=true;break;}
            pollfd fds[2]{{STDIN_FILENO,POLLIN,0},{STDOUT_FILENO,short(output.records.empty()?0:POLLOUT),0}};
            // Same bounded private-loop wait as the verified transport seam;
            // output is nonblocking so an unread owner pipe cannot block Stop.
            auto ready=poll(fds,2,g_main_context_pending(nullptr)?0:5);if(ready<0){if(errno==EINTR)continue;throw std::runtime_error("Private worker poll failed");}
            if(fds[0].revents&(POLLIN|POLLHUP|POLLERR)) {
                char bytes[4096];auto count=read(STDIN_FILENO,bytes,sizeof(bytes));
                if(!count){owner_gone=true;break;}
                if(count<0){if(errno==EINTR || errno==EAGAIN || errno==EWOULDBLOCK)continue;owner_gone=true;break;}
                pending.append(bytes,count);
                for(std::size_t end;(end=pending.find('\n'))!=std::string::npos;) {
                    auto line=pending.substr(0,end);pending.erase(0,end+1);auto message=json::parse(line);
                    if(!transport) {
                        config=traverse::ReadinessMediaConfig::parse(message);
                        if(!config->source && config->port>=1024)traverse::drop_bind_privilege();
                        gst_init(nullptr,nullptr);
                        transport=std::make_unique<traverse::ReadinessMediaTransport>(*config);
                    } else if(message.is_object() && message.size()==2 && message.contains("schemaVersion") && message.at("schemaVersion").is_number_integer() && message.at("schemaVersion")==1 && message.contains("type") && message.at("type")=="stop") {
                        requested_stop=true;break;
                    } else transport->command(message);
                }
            }
        }
        const bool failed=transport && transport->failed();
        if(transport){transport->stop();for(auto &event:transport->events())output.add(event);}
        if(config)output.add({{"schemaVersion",1},{"type","stopped"},{"peer",config->peer},{"port",config->port}});
        while(!owner_gone && !stopping && !output.records.empty()) {
            if(!output.flush())break;
            if(output.records.empty())break;
            pollfd fds[2]{{STDOUT_FILENO,POLLOUT,0},{STDIN_FILENO,POLLIN,0}};
            if(poll(fds,2,5)<0 && errno!=EINTR)break;
            if(fds[1].revents&(POLLHUP|POLLERR))break;
        }
        return failed?1:0;
    } catch(...) {
        // No SDP, URI, key or credential is printed on failure.
        const char failure[]="{\"schemaVersion\":1,\"type\":\"failure\",\"reason\":\"invalidRequest\"}\n";
        auto count=write(STDOUT_FILENO,failure,sizeof(failure)-1);(void)count;return 1;
    }
}
