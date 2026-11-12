#include "wayland_controller.hpp"
#include "change_notification.hpp"
#include <cerrno>
#include <cstring>
#include <deque>
#include <filesystem>
#include <limits>
#include <map>
#include <mutex>
#include <poll.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

extern char **environ;
namespace traverse {
namespace {
using Json=nlohmann::json;
void drain(int fd) {
    char data[256];
    for (;;) {
        auto count=read(fd,data,sizeof(data));
        if (count>0 || (count<0 && errno==EINTR)) continue;
        return;
    }
}
std::uint64_t identity(const Json &value) {
    if (value.is_number_unsigned()) return value.get<std::uint64_t>();
    if (value.is_number_integer() && value.get<std::int64_t>()>0)
        return static_cast<std::uint64_t>(value.get<std::int64_t>());
    throw WaylandController::Error(WaylandController::Failure::Protocol,"Invalid worker response identity");
}
void validate_snapshot(const Json &value) {
    if (!value.is_object() || !value.contains("state") || !value["state"].is_string() ||
        !value.contains("granted") || !value["granted"].is_boolean() ||
        !value.contains("inputReady") || !value["inputReady"].is_boolean() ||
        !value.contains("stopping") || !value["stopping"].is_boolean() ||
        !value.contains("error") || !value["error"].is_string() ||
        !value.contains("inputMethod") || !value["inputMethod"].is_string() ||
        !value.contains("streams") || !value["streams"].is_array() ||
        (value["inputReady"].get<bool>() && (!value["granted"].get<bool>() || value["stopping"].get<bool>())))
        throw WaylandController::Error(WaylandController::Failure::Protocol,"Invalid native desktop snapshot");
    const auto state=value["state"].get<std::string>(),method=value["inputMethod"].get<std::string>();
    if ((state!="probing" && state!="capabilities-ready" && state!="requesting" &&
         state!="waiting-permission" && state!="granted" && state!="not-granted" &&
         state!="failed" && state!="stopped" && state!="closed") ||
        value["granted"].get<bool>()!=(state=="granted") ||
        (method!="undetermined" && method!="portal-dbus" && method!="eis"))
        throw WaylandController::Error(WaylandController::Failure::Protocol,"Inconsistent native authority state");
    if (value["inputReady"].get<bool>()) {
        const auto selected=value.find("selectedStream");
        if (method=="undetermined" || selected==value.end() || !selected->is_number_integer() ||
            (!selected->is_number_unsigned() && selected->get<std::int64_t>()<0) ||
            selected->get<std::uint64_t>()>=value["streams"].size())
            throw WaylandController::Error(WaylandController::Failure::Protocol,"Input readiness lacks a granted stream");
    }
}
}

struct WaylandController::Impl {
    struct Pending {
        std::promise<Json> result;
        std::uint64_t id=0;
        std::string bytes;
        std::size_t sent=0;
        bool dispatched=false;
    };
    mutable std::mutex mutex;
    ChangeNotification changed,wake;
    std::string executable,incoming;
    Snapshot value;
    bool stopping=false,finished=false,started=false,ended=false,reaped=false;
    std::optional<Failure> failure;
    std::uint64_t next=0;
    std::map<std::uint64_t,std::shared_ptr<Pending>> pending;
    std::deque<std::shared_ptr<Pending>> outgoing;
    std::promise<void> stopped;
    std::shared_future<void> stop_result=stopped.get_future().share();
    std::thread lifecycle,reaper;
    int control=-1;

    explicit Impl(std::string path):executable(std::move(path)) {
        if (!std::filesystem::path(executable).is_absolute() || executable.find('\0')!=std::string::npos)
            throw std::invalid_argument("Worker requires an absolute executable path");
        lifecycle=std::thread([this] {run();});
    }
    ~Impl() {
        request_stop();
        if (lifecycle.joinable()) lifecycle.join();
    }
    void request_stop() {
        {std::lock_guard lock(mutex);stopping=true;value.accepting=false;}
        wake.notify();changed.notify();
    }
    std::future<Json> submit(Json command) {
        auto item=std::make_shared<Pending>();auto future=item->result.get_future();
        try {
            if (!command.is_object() || !command.contains("op") || !command["op"].is_string() ||
                command.contains("id") || command.contains("schemaVersion"))
                throw Error(Failure::Protocol,"Controller command must contain op without caller identity/schema");
            {
                std::lock_guard lock(mutex);
                if (stopping || finished) throw Error(Failure::Cancelled,"Controller is stopping");
                if (next==std::numeric_limits<std::uint64_t>::max())
                    throw Error(Failure::Protocol,"Controller request identity cannot be represented");
                item->id=++next;command["id"]=item->id;command["schemaVersion"]=1;
                item->bytes=command.dump()+"\n";
                outgoing.push_back(item);
                try {pending.emplace(item->id,item);}
                catch (...) {outgoing.pop_back();throw;}
            }
            wake.notify();
        } catch (...) {item->result.set_exception(std::current_exception());changed.notify();}
        return future;
    }
    void fault(Failure kind,const std::string &reason) {
        std::lock_guard lock(mutex);
        if (!failure) {failure=kind;value.error=reason;}
        stopping=true;value.accepting=false;changed.notify();
    }
    void spawn_worker() {
        int sockets[2];
        if (socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,sockets))
            throw Error(Failure::Spawn,"Cannot create worker control socket");
        struct Pair {
            int *fds;
            ~Pair(){for(int i=0;i<2;++i)if(fds[i]>=0)close(fds[i]);}
        } owned{sockets};
        for (int i=0;i<2;++i) if (sockets[i]<3) {
            int moved=fcntl(sockets[i],F_DUPFD_CLOEXEC,3);
            if (moved<0) throw Error(Failure::Spawn,"Cannot reserve worker socket");
            close(sockets[i]);sockets[i]=moved;
        }
        int flags=fcntl(sockets[0],F_GETFL);
        if (flags<0 || fcntl(sockets[0],F_SETFL,flags|O_NONBLOCK))
            throw Error(Failure::Spawn,"Cannot prepare nonblocking worker socket");
        struct Actions {
            posix_spawn_file_actions_t data;
            Actions(){if(posix_spawn_file_actions_init(&data))throw Error(Failure::Spawn,"Cannot prepare worker descriptors");}
            ~Actions(){posix_spawn_file_actions_destroy(&data);}
        } actions;
        if (posix_spawn_file_actions_adddup2(&actions.data,sockets[1],STDIN_FILENO) ||
            posix_spawn_file_actions_addopen(&actions.data,STDOUT_FILENO,"/dev/null",O_WRONLY,0) ||
            posix_spawn_file_actions_addclosefrom_np(&actions.data,3))
            throw Error(Failure::Spawn,"Cannot isolate worker descriptors");
        auto parent=std::to_string(getpid());
        char *arguments[]={const_cast<char *>(executable.c_str()),const_cast<char *>(parent.c_str()),nullptr};
        pid_t pid=-1;
        int result=posix_spawn(&pid,executable.c_str(),&actions.data,nullptr,arguments,environ);
        if (result) throw Error(Failure::Spawn,std::string("Cannot execute worker: ")+std::strerror(result));
        control=sockets[0];sockets[0]=-1;
        {std::lock_guard lock(mutex);value.worker_pid=pid;}
        // This lifecycle thread is the child's creator. It stays alive until
        // reaping, including when the original constructor's caller exits.
        try {
            reaper=std::thread([this,pid] {
                int status=0;pid_t result;
                do {result=waitpid(pid,&status,0);} while(result<0 && errno==EINTR);
                {
                    std::lock_guard lock(mutex);
                    reaped=true;stopping=true;value.accepting=false;
                    if (result==pid) value.exit_status=WIFEXITED(status)?WEXITSTATUS(status):-WTERMSIG(status);
                    else if (!failure) {failure=Failure::ChildExit;value.error="Worker could not be reaped";}
                }
                wake.notify();changed.notify();
            });
        } catch (...) {
            close(control);control=-1;
            int status;while(waitpid(pid,&status,0)<0 && errno==EINTR) {}
            throw;
        }
    }
    void message(const Json &row) {
        std::lock_guard lock(mutex);
        if (!row.is_object() || !row.contains("schemaVersion") || !row["schemaVersion"].is_number_integer() ||
            row["schemaVersion"]!=1 || !row.contains("id") || ended)
            throw Error(Failure::Protocol,"Invalid worker message schema/order");
        if (row["id"].is_null()) {
            if (!row.contains("event") || !row["event"].is_string())
                throw Error(Failure::Protocol,"Invalid worker event");
            auto event=row["event"].get<std::string>();
            if (event=="started") {
                if (started || !row.contains("pid") || identity(row["pid"])!=static_cast<std::uint64_t>(value.worker_pid) ||
                    !row.contains("ok") || !row["ok"].is_boolean() || !row["ok"].get<bool>())
                    throw Error(Failure::Protocol,"Invalid worker startup identity");
                started=true;value.accepting=!stopping;
            } else if ((event=="state" || event=="ended") && started) {
                if (!row.contains("snapshot")) throw Error(Failure::Protocol,"Missing native desktop snapshot");
                validate_snapshot(row["snapshot"]);
                if (event=="ended" && (row["snapshot"]["granted"].get<bool>() || !row["snapshot"]["stopping"].get<bool>()))
                    throw Error(Failure::Protocol,"Worker ended without terminal authority state");
                value.desktop=row["snapshot"];
                if (row["snapshot"]["stopping"].get<bool>()) {stopping=true;value.accepting=false;}
                if (event=="ended") ended=true;
            } else throw Error(Failure::Protocol,"Unexpected worker event");
        } else {
            auto id=identity(row["id"]);auto found=pending.find(id);
            if (!started || found==pending.end() || !found->second->dispatched ||
                !row.contains("ok") || !row["ok"].is_boolean() ||
                (!row["ok"].get<bool>() && (!row.contains("error") || !row["error"].is_string())))
                throw Error(Failure::Protocol,"Invalid or unknown worker response");
            if (row.contains("snapshot")) validate_snapshot(row["snapshot"]);
            found->second->result.set_value(row);pending.erase(found);
        }
        changed.notify();
    }
    enum class Read { Progress, Idle, Closed };
    Read receive() {
        char bytes[8192];
        for (;;) {
            auto count=recv(control,bytes,sizeof(bytes),MSG_DONTWAIT);
            if (count==0) {
                if (!incoming.empty()) throw Error(Failure::Protocol,"Truncated worker message");
                return Read::Closed;
            }
            if (count<0) {
                if(errno==EINTR)continue;
                if(errno==EAGAIN || errno==EWOULDBLOCK)return Read::Idle;
                throw Error(Failure::Transport,"Worker receive failed");
            }
            incoming.append(bytes,static_cast<std::size_t>(count));
            for (std::size_t newline;(newline=incoming.find('\n'))!=std::string::npos;) {
                auto line=incoming.substr(0,newline);incoming.erase(0,newline+1);
                try {message(Json::parse(line));}
                catch(const Error &){throw;}
                catch(const std::exception &){throw Error(Failure::Protocol,"Malformed worker message");}
            }
            return Read::Progress;
        }
    }
    void write_pending() {
        std::lock_guard lock(mutex);
        if (!outgoing.empty() && started && !stopping) {
            auto &item=outgoing.front();
            ssize_t count;
            do {count=send(control,item->bytes.data()+item->sent,item->bytes.size()-item->sent,MSG_NOSIGNAL|MSG_DONTWAIT);}while(count<0 && errno==EINTR);
            if(count>0) {
                item->sent+=static_cast<std::size_t>(count);
                if(item->sent==item->bytes.size()){item->dispatched=true;outgoing.pop_front();}
            } else if(count<0 && (errno==EAGAIN || errno==EWOULDBLOCK))return;
            else throw Error(Failure::Transport,"Worker send failed");
        }
    }
    void cancel_unsent() {
        std::lock_guard lock(mutex);
        for (auto &item:outgoing) {
            item->result.set_exception(std::make_exception_ptr(Error(Failure::Cancelled,"Unsent worker operation cancelled")));
            pending.erase(item->id);
        }
        outgoing.clear();changed.notify();
    }
    void run() noexcept {
        try {
            bool skip;
            {std::lock_guard lock(mutex);skip=stopping;}
            if (!skip) {
                spawn_worker();bool write_closed=false,open=true;
                while (open) {
                    bool stop,child_done,writes;
                    {std::lock_guard lock(mutex);stop=stopping;child_done=reaped;writes=started&&!outgoing.empty();}
                    if (stop && !write_closed) {
                        cancel_unsent();shutdown(control,SHUT_WR);write_closed=true;
                    }
                    if (child_done) {
                        auto result=receive();
                        if(result==Read::Progress)continue;
                        break;
                    }
                    pollfd items[]={{wake.descriptor(),POLLIN,0},{control,short(POLLIN|(!write_closed&&writes?POLLOUT:0)),0}};
                    int ready;do{ready=poll(items,2,-1);}while(ready<0 && errno==EINTR);
                    if(ready<0)throw Error(Failure::Transport,"Controller poll failed");
                    if(items[0].revents) {drain(wake.descriptor());continue;}
                    if(items[1].revents&(POLLIN|POLLHUP))open=receive()!=Read::Closed;
                    if(open && (items[1].revents&POLLOUT))write_pending();
                    if(items[1].revents&(POLLERR|POLLNVAL))throw Error(Failure::Transport,"Worker socket failed");
                }
            }
        } catch (const Error &error) {fault(error.failure,error.what());}
        catch (const std::exception &error) {fault(Failure::Transport,error.what());}
        catch (...) {fault(Failure::Transport,"Controller failed");}
        if(control>=0){close(control);control=-1;}
        if(reaper.joinable())reaper.join();
        std::lock_guard lock(mutex);
        if(value.worker_pid>0 && !failure) {
            if(!value.exit_status || *value.exit_status!=0) {
                failure=Failure::ChildExit;
                value.error=value.desktop && !value.desktop->value("error",std::string{}).empty() ?
                    value.desktop->value("error",std::string{}) : "Worker exited unsuccessfully";
            } else if(!ended){failure=Failure::Protocol;value.error="Worker exited without terminal state";}
        }
        stopping=true;finished=true;value.accepting=false;value.terminal=true;
        for(auto &[id,item]:pending) {
            (void)id;
            item->result.set_exception(std::make_exception_ptr(Error(failure.value_or(Failure::Cancelled),
                failure?value.error:"Worker operation ended before completion")));
        }
        pending.clear();outgoing.clear();
        if(failure)stopped.set_exception(std::make_exception_ptr(Error(*failure,value.error)));
        else stopped.set_value();
        changed.notify();
    }
};
WaylandController::WaylandController(std::string path):impl(std::make_unique<Impl>(std::move(path))) {}
WaylandController::~WaylandController() noexcept=default;
std::future<Json> WaylandController::request(Json command){return impl->submit(std::move(command));}
std::shared_future<void> WaylandController::stop(){impl->request_stop();return impl->stop_result;}
WaylandController::Snapshot WaylandController::snapshot() const {std::lock_guard lock(impl->mutex);return impl->value;}
int WaylandController::state_descriptor() const noexcept{return impl->changed.descriptor();}
}
