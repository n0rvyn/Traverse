#include "readiness_media.hpp"
#include "readiness_media_transport.hpp"
#include "probe_relay_broker.hpp"
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <deque>
#include <fcntl.h>
#include <mutex>
#include <optional>
#include <poll.h>
#include <set>
#include <spawn.h>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
extern char **environ;

namespace traverse {
namespace {
using Json = nlohmann::json;
using Clock = std::chrono::steady_clock;
bool identity(const std::string &id) {
    return id.size()==32 && id.find_first_not_of("0123456789abcdef")==std::string::npos;
}
class SourceProcess {
    int channel=-1;
    pid_t pid=-1;
    std::optional<Clock::time_point> cancellation;
    bool killed=false;
  public:
    explicit SourceProcess(const std::filesystem::path &binary) {
        int pair[2];
        if(socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,pair))
            throw std::runtime_error("Cannot create synthetic source channel");
        int parent=fcntl(pair[0],F_DUPFD_CLOEXEC,3),child=fcntl(pair[1],F_DUPFD_CLOEXEC,3);
        close(pair[0]);close(pair[1]);
        if(parent<0 || child<0) {
            if(parent>=0)close(parent);
            if(child>=0)close(child);
            throw std::runtime_error("Cannot prepare synthetic source channel");
        }
        posix_spawn_file_actions_t actions;
        int error=posix_spawn_file_actions_init(&actions);
        const bool initialized=!error;
        if(!error)error=posix_spawn_file_actions_adddup2(&actions,child,STDIN_FILENO);
        if(!error)error=posix_spawn_file_actions_adddup2(&actions,child,STDOUT_FILENO);
        if(!error)error=posix_spawn_file_actions_addopen(&actions,STDERR_FILENO,"/dev/null",O_WRONLY,0);
        // The service owns desktop/owner/listener FDs. None cross this boundary,
        // including descriptors accidentally left without CLOEXEC by a caller.
        if(!error)error=posix_spawn_file_actions_addclosefrom_np(&actions,3);
        auto executable=binary.string(),supervisor=std::to_string(getpid());
        char option[]="--supervisor-pid";
        char *arguments[]={executable.data(),option,supervisor.data(),nullptr};
        std::vector<std::string> environment;
        const std::set<std::string> runtime_variables={
            "LD_LIBRARY_PATH","GST_PLUGIN_PATH_1_0","GST_PLUGIN_SYSTEM_PATH_1_0",
            "GST_PLUGIN_SCANNER","GST_PLUGIN_SCANNER_1_0","GST_REGISTRY","GST_REGISTRY_1_0",
            "GST_REGISTRY_UPDATE","XDG_CACHE_HOME","LANG","LC_ALL"};
        for(auto entry=environ;*entry;++entry) {
            std::string value=*entry;auto key=value.substr(0,value.find('='));
            if(runtime_variables.count(key))
                environment.push_back(std::move(value));
        }
        std::vector<char *> variables;
        for(auto &entry:environment)variables.push_back(entry.data());
        variables.push_back(nullptr);
        if(!error)error=posix_spawn(&pid,executable.c_str(),&actions,nullptr,arguments,variables.data());
        if(initialized)posix_spawn_file_actions_destroy(&actions);
        close(child);
        if(error) {close(parent);pid=-1;throw std::runtime_error("Cannot start synthetic source");}
        channel=parent;
        int flags=fcntl(channel,F_GETFL);
        if(flags<0 || fcntl(channel,F_SETFL,flags|O_NONBLOCK)) {
            cancel();reap_blocking();close(channel);channel=-1;
            throw std::runtime_error("Cannot monitor synthetic source");
        }
    }
    ~SourceProcess() {cancel();reap_blocking();if(channel>=0)close(channel);}
    int fd() const {return channel;}
    void cancel() {
        if(pid>0 && !cancellation) {
            cancellation=Clock::now();kill(pid,SIGTERM);shutdown(channel,SHUT_WR);
        }
    }
    std::optional<int> reap() {
        if(pid<=0)return std::nullopt;
        // Same owned-child shutdown escalation as the existing supervisor.
        if(cancellation && !killed && Clock::now()-*cancellation>=std::chrono::seconds(5)) {
            kill(pid,SIGKILL);killed=true;
        }
        int status=0;auto result=waitpid(pid,&status,WNOHANG);
        if(result==pid) {pid=-1;return WIFEXITED(status)?WEXITSTATUS(status):128+WTERMSIG(status);}
        if(result<0 && errno!=EINTR)throw std::runtime_error("Cannot reap synthetic source");
        return std::nullopt;
    }
  private:
    void reap_blocking() noexcept {
        while(pid>0) {
            try {if(reap())break;} catch(...) {pid=-1;break;}
            poll(nullptr,0,5);
        }
    }
};
}
struct ReadinessMedia::State {
    const std::filesystem::path worker;
    const std::string broker;
    const ReadinessMediaRole role;
    mutable std::mutex mutex;
    std::mutex stop_mutex;
    std::mutex priority_mutex;
    std::mutex allocation_mutex;
    std::condition_variable changed;
    bool stopping=false,controller=false,busy=false,cancelled=false;
    std::string current;
    std::optional<Json> pending;
    std::optional<ReadinessProbeRelayGrant> pending_relay;
    bool relay_ready=false,source_started=false,allocation_request=false,allocation_done=false;
    bool quiescence_failed=false;
    std::atomic<bool> broker_cancel{false};
    std::vector<ReadinessMediaPeer> allocated;
    std::deque<Json> commands;
    std::vector<Json> output;
    std::set<std::string> ended;
    std::thread owner;
    explicit State(std::filesystem::path binary,std::string channel,ReadinessMediaRole purpose)
        :worker(std::move(binary)),broker(std::move(channel)),role(purpose) {
        if(!worker.is_absolute())throw std::runtime_error("Synthetic worker path must be absolute");
        if(!broker.empty() && !std::filesystem::path(broker).is_absolute())throw std::runtime_error("Private relay broker path must be absolute");
        if(role==ReadinessMediaRole::Observer && !broker.empty())throw std::runtime_error("Observer cannot own a source relay");
        owner=std::thread([this]{run();});
    }
    ~State(){stop();}
    void publish(const std::string &id,Json event) {
        std::lock_guard lock(mutex);
        if(event.value("type",std::string{})=="failure" && !event.contains("peer"))event["peer"]=id;
        if(current==id && !cancelled && !stopping && !controller)output.push_back(std::move(event));
    }
    void run_job(const std::string &id,Json config) {
        SourceProcess process(worker);
        std::deque<std::string> sending{config.dump()+'\n'};
        std::size_t offset=0;
        std::string input;
        bool cancelling=false;
        while(true) {
            {
                std::lock_guard lock(mutex);
                if(stopping || cancelled || controller)cancelling=true;
                if(!cancelling) {
                    while(!commands.empty()) {sending.push_back(commands.front().dump()+'\n');commands.pop_front();}
                }
            }
            if(cancelling){sending.clear();process.cancel();}
            pollfd event{process.fd(),static_cast<short>(POLLIN|(!sending.empty()?POLLOUT:0)),0};
            int ready=poll(&event,1,5);
            if(ready<0 && errno!=EINTR)throw std::runtime_error("Synthetic source channel failed");
            if(!sending.empty() && (event.revents&POLLOUT)) {
                auto &text=sending.front();auto count=send(process.fd(),text.data()+offset,text.size()-offset,MSG_NOSIGNAL);
                if(count>0) {offset+=count;if(offset==text.size()){sending.pop_front();offset=0;}}
                else if(count<0 && errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=EINTR)cancelling=true;
            }
            if(event.revents&(POLLIN|POLLHUP|POLLERR)) {
                char bytes[4096];auto count=recv(process.fd(),bytes,sizeof(bytes),0);
                if(count>0) {
                    input.append(bytes,count);
                    for(std::size_t end;(end=input.find('\n'))!=std::string::npos;) {
                        auto text=input.substr(0,end);input.erase(0,end+1);
                        auto message=Json::parse(text);
                        if(!message.is_object() || message.value("schemaVersion",0)!=1 || !message.contains("type"))
                            throw std::runtime_error("Invalid synthetic source event");
                        if(message.at("type")!="failure" && (message.value("peer",std::string{})!=id || message.at("port")!=config.at("port")))
                            throw std::runtime_error("Wrong synthetic source identity");
                        publish(id,message);
                        if(message.at("type")=="failure")cancelling=true;
                    }
                } else if(!count || (errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=EINTR))cancelling=true;
            }
            auto result=process.reap();
            if(result) {
                if(*result && !cancelling)throw std::runtime_error("Synthetic source exited");
                return;
            }
        }
    }
    void run_relay_job(const std::string &id,const ReadinessProbeRelayGrant &grant) {
        ReadinessProbeTurn relay(worker.parent_path()/"turnserver",grant.addresses,
            grant.source_port,grant.username,grant.credential);
        std::unique_ptr<ProbeRelayLease> route;
        auto release_route=[&] {
            if(broker.empty())return;
            std::atomic<bool> cleanup{false};
            const bool drained=route?route->end(cleanup):ProbeRelayLease::cancel_reserved(broker,grant.route,cleanup);
            if(!drained){std::lock_guard lock(mutex);quiescence_failed=true;}
        };
        bool announced=false;
        try {
        while(true) {
            bool inspect=false;std::optional<Json> config;
            {
                std::lock_guard lock(mutex);
                if(stopping || cancelled || controller)break;
                inspect=allocation_request;allocation_request=false;
                if(pending){config=std::move(pending);pending.reset();source_started=true;}
            }
            if(!announced && relay.ready()) {
                if(!broker.empty())route=std::make_unique<ProbeRelayLease>(broker,grant.route,relay.port(),broker_cancel);
                {std::lock_guard lock(mutex);relay_ready=true;changed.notify_all();}
                publish(id,{{"schemaVersion",1},{"type","relayReady"},{"peer",id},
                    {"port",grant.source_port},{"backend",relay.port()}});
                announced=true;
            }
            if(inspect) {
                auto sockets=relay.allocations();
                std::lock_guard lock(mutex);allocated=std::move(sockets);allocation_done=true;changed.notify_all();
            }
            if(config) {
                // The real source must still take the exact granted port.
                if(config->at("port")!=grant.source_port)throw std::runtime_error("Wrong relay source port");
                run_job(id,std::move(*config));break;
            }
            // Also detects a failed child after its first readiness event.
            if(announced && !relay.ready())throw std::runtime_error("Probe relay listener lost");
            std::unique_lock lock(mutex);
            changed.wait_for(lock,std::chrono::milliseconds(5),[&]{return stopping || cancelled || controller || pending || allocation_request;});
        }
        } catch(...) {release_route();throw;}
        release_route();
        relay.stop(); // Reaped before busy becomes false or preempt returns.
    }
    void run() {
        while(true) {
            std::string id;Json config;std::optional<ReadinessProbeRelayGrant> relay;
            {
                std::unique_lock lock(mutex);
                changed.wait(lock,[&]{return stopping || pending.has_value() || pending_relay.has_value();});
                if(stopping && !pending && !pending_relay)return;
                id=current;
                if(pending_relay){relay=std::move(pending_relay);pending_relay.reset();}
                else {config=std::move(*pending);pending.reset();source_started=true;}
                if(cancelled || stopping || controller) {
                    busy=false;changed.notify_all();continue;
                }
            }
            try {if(relay)run_relay_job(id,*relay);else run_job(id,std::move(config));}
            catch(...) {publish(id,{{"schemaVersion",1},{"type","failure"},{"peer",id},{"reason","sourceUnavailable"}});}
            {
                std::lock_guard lock(mutex);
                ended.insert(id);busy=false;relay_ready=false;source_started=false;pending.reset();commands.clear();changed.notify_all();
            }
        }
    }
    void stop() {
        std::lock_guard stop_lock(stop_mutex);
        {std::lock_guard lock(mutex);stopping=true;cancelled=true;broker_cancel=true;output.clear();changed.notify_all();}
        if(owner.joinable())owner.join();
    }
};
ReadinessMedia::ReadinessMedia(std::filesystem::path worker,std::string broker,ReadinessMediaRole role)
    :state(std::make_unique<State>(std::move(worker),std::move(broker),role)) {}
ReadinessMedia::~ReadinessMedia()=default;
bool ReadinessMedia::begin(const std::string &id,const Json &config) {
    auto parsed=ReadinessMediaConfig::parse(config);
    const bool source=state->role==ReadinessMediaRole::Source;
    if(!identity(id) || id!=parsed.peer || parsed.source!=source || (source && parsed.relay))
        throw std::runtime_error("Invalid synthetic source request");
    std::lock_guard lock(state->mutex);
    if(state->stopping || state->controller || state->quiescence_failed || state->ended.count(id))return false;
    if(state->busy) {
        if(state->cancelled || state->current!=id || !state->relay_ready || state->source_started || state->pending)return false;
        state->pending=config;state->changed.notify_all();return true;
    }
    state->pending=config;state->current=id;state->cancelled=false;state->busy=true;state->commands.clear();state->output.clear();state->changed.notify_all();return true;
}
bool ReadinessMedia::prepare_relay(const std::string &id,const ReadinessProbeRelayGrant &grant) {
    auto hex=[](const std::string &value){return value.size()==64 && value.find_first_not_of("0123456789abcdef")==std::string::npos;};
    if(state->role!=ReadinessMediaRole::Source)throw std::runtime_error("Observer cannot own a source relay");
    if(!identity(id) || !grant.source_port || grant.addresses.empty() || !hex(grant.username) || !hex(grant.credential))
        throw std::runtime_error("Invalid probe relay grant");
    if(!state->broker.empty() && !hex(grant.route))throw std::runtime_error("Invalid probe relay route");
    std::lock_guard lock(state->mutex);
    if(state->stopping || state->controller || state->quiescence_failed || state->busy || state->ended.count(id))return false;
    state->pending_relay=grant;state->current=id;state->cancelled=false;state->busy=true;
    state->relay_ready=false;state->source_started=false;state->allocation_request=false;state->broker_cancel=false;state->commands.clear();state->output.clear();state->changed.notify_all();return true;
}
std::optional<std::vector<ReadinessMediaPeer>> ReadinessMedia::relay_allocations(const std::string &id) {
    std::lock_guard request(state->allocation_mutex);
    std::unique_lock lock(state->mutex);
    if(!state->busy || state->current!=id || !state->relay_ready || state->source_started || state->cancelled || state->controller || state->stopping)return std::nullopt;
    state->allocation_done=false;state->allocation_request=true;state->changed.notify_all();
    state->changed.wait(lock,[&]{return state->allocation_done || !state->busy || state->current!=id || state->cancelled || state->stopping || state->controller;});
    if(!state->allocation_done || state->cancelled || state->stopping || state->controller)return std::nullopt;
    return state->allocated;
}
bool ReadinessMedia::command(const std::string &id,const Json &value) {
    std::lock_guard lock(state->mutex);
    if(!state->busy || state->current!=id || state->cancelled || state->controller || state->stopping)return false;
    state->commands.push_back(value);state->changed.notify_all();return true;
}
std::vector<Json> ReadinessMedia::events() {
    std::lock_guard lock(state->mutex);
    auto result=std::move(state->output);state->output.clear();return result;
}
void ReadinessMedia::end(const std::string &id) {
    if(!identity(id))throw std::runtime_error("Invalid synthetic source identity");
    std::unique_lock lock(state->mutex);state->ended.insert(id);
    if(state->current==id)state->output.clear();
    if(state->busy && state->current==id){state->cancelled=true;state->broker_cancel=true;state->changed.notify_all();}
    state->changed.wait(lock,[&]{return !state->busy || state->current!=id;});
    if(state->quiescence_failed)throw std::runtime_error("Probe relay cleanup not acknowledged");
}
void ReadinessMedia::preempt() {
    std::lock_guard priority_lock(state->priority_mutex);
    std::unique_lock lock(state->mutex);state->controller=true;state->cancelled=true;
    state->broker_cancel=true;
    state->output.clear();
    if(state->busy)state->ended.insert(state->current);
    state->changed.notify_all();state->changed.wait(lock,[&]{return !state->busy;});
    if(state->quiescence_failed)throw std::runtime_error("Probe relay cleanup not acknowledged");
}
void ReadinessMedia::owner_revoked_controller() {
    std::lock_guard priority_lock(state->priority_mutex);
    std::lock_guard lock(state->mutex);if(!state->stopping)state->controller=false;
}
bool ReadinessMedia::idle() const {std::lock_guard lock(state->mutex);return !state->busy;}
void ReadinessMedia::stop(){state->stop();}
}
