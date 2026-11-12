#include "wayland_guardian.hpp"
#include "portal_session.hpp"
#include "eis_input.hpp"
#include "capture_backend.hpp"
#include "input_keys.hpp"
#include <nlohmann/json.hpp>
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <deque>
#include <fcntl.h>
#include <iostream>
#include <limits>
#include <optional>
#include <poll.h>
#include <set>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <sys/un.h>
#include <unistd.h>

namespace traverse {
namespace {
using Json=nlohmann::json;
using Session=PortalSession;
using Clock=std::chrono::steady_clock;
volatile sig_atomic_t signal_writer=-1;
void interrupted(int) {
    int saved=errno;
    const char byte=1;
    if (signal_writer>=0) {
        ssize_t ignored=write(signal_writer,&byte,1);
        (void)ignored;
    }
    errno=saved;
}
struct Signals {
    int pipe[2]{-1,-1};
    struct sigaction previous_term{},previous_int{};
    Signals() {
        if (pipe2(pipe,O_NONBLOCK|O_CLOEXEC)) throw std::runtime_error("Guardian signal channel unavailable");
        struct sigaction action{};
        action.sa_handler=interrupted;sigemptyset(&action.sa_mask);
        signal_writer=pipe[1];
        if (sigaction(SIGTERM,&action,&previous_term)) {
            signal_writer=-1;
            close(pipe[0]);close(pipe[1]);throw std::runtime_error("Guardian signal handler unavailable");
        }
        if (sigaction(SIGINT,&action,&previous_int)) {
            signal_writer=-1;
            sigaction(SIGTERM,&previous_term,nullptr);
            close(pipe[0]);close(pipe[1]);throw std::runtime_error("Guardian signal handler unavailable");
        }
    }
    ~Signals() {
        signal_writer=-1;
        sigaction(SIGTERM,&previous_term,nullptr);sigaction(SIGINT,&previous_int,nullptr);
        close(pipe[0]);close(pipe[1]);
    }
};
void drain(int fd) {
    char bytes[256];
    for (;;) {
        auto count=read(fd,bytes,sizeof(bytes));
        if (count>0 || (count<0 && errno==EINTR)) continue;
        if (count<0 && (errno==EAGAIN || errno==EWOULDBLOCK)) return;
        throw std::runtime_error("Guardian notification channel ended");
    }
}
void verify_controller(int fd,pid_t parent) {
    int type=0;socklen_t size=sizeof(type);
    sockaddr_un address{};socklen_t length=sizeof(address);
    ucred peer{};socklen_t peer_size=sizeof(peer);
    if (parent<=1 || getppid()!=parent || getsockopt(fd,SOL_SOCKET,SO_TYPE,&type,&size) ||
        type!=SOCK_STREAM || getpeername(fd,reinterpret_cast<sockaddr *>(&address),&length) ||
        address.sun_family!=AF_UNIX || getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&peer,&peer_size) ||
        peer_size!=sizeof(peer) || peer.uid!=geteuid() || peer.pid!=parent)
        throw std::runtime_error("Guardian requires its exclusive inherited controller socket");
    int flags=fcntl(fd,F_GETFL),descriptor_flags=fcntl(fd,F_GETFD);
    if (flags<0 || descriptor_flags<0 || fcntl(fd,F_SETFL,flags|O_NONBLOCK) ||
        fcntl(fd,F_SETFD,descriptor_flags|FD_CLOEXEC) ||
        prctl(PR_SET_PDEATHSIG,SIGTERM) || getppid()!=parent)
        throw std::runtime_error("Cannot protect guardian controller descriptor");
}
std::int64_t integer(const Json &value,std::int64_t minimum,std::int64_t maximum) {
    if (!value.is_number_integer()) throw std::runtime_error("Invalid integer field");
    if (value.is_number_unsigned()) {
        auto number=value.get<std::uint64_t>();
        if (maximum<0 || number>static_cast<std::uint64_t>(maximum) ||
            (minimum>0 && number<static_cast<std::uint64_t>(minimum)))
            throw std::runtime_error("Integer field out of range");
        return static_cast<std::int64_t>(number);
    }
    auto number=value.get<std::int64_t>();
    if (number<minimum || number>maximum) throw std::runtime_error("Integer field out of range");
    return number;
}
const char *session_name(Session::State state) {
    switch (state) {
    case Session::State::Probing:return "probing";
    case Session::State::CapabilitiesReady:return "capabilities-ready";
    case Session::State::Requesting:return "requesting";
    case Session::State::WaitingPermission:return "waiting-permission";
    case Session::State::Granted:return "granted";
    case Session::State::NotGranted:return "not-granted";
    case Session::State::Failed:return "failed";
    case Session::State::Stopped:return "stopped";
    case Session::State::Closed:return "closed";
    }
    return "unknown";
}
class Guardian {
    int control;
    Signals signals;
    Session session;
    std::unique_ptr<EisInput> eis;
    std::unique_ptr<PipeWireCapture> capture;
    std::optional<std::size_t> selected;
    struct CaptureStart {
        Json id;
        std::future<Session::Connection> connection;
        Session::Stream stream;
        PipeWireCapture::Options options;
    };
    std::optional<CaptureStart> starting_capture;
    std::optional<Json> capture_response;
    struct Work {
        Json id;
        std::vector<std::future<void>> operations;
        bool release=false;
        std::string error;
        bool idempotent_edge=false;
    };
    std::deque<Work> pending;
    std::set<int> keys,buttons;
    std::string incoming,outgoing,terminal_error;
    Json published_material;
    std::size_t sent=0;
    bool stopping=false,cleanup_pending=false;
    Clock::time_point last_input=Clock::now(),idle_release=last_input+std::chrono::seconds(3);

    void reply(const Json &id,Json body) {
        body["schemaVersion"]=1;body["id"]=id;
        outgoing+=body.dump()+"\n";
    }
    Json snapshot() const {
        auto value=session.snapshot();
        Json streams=Json::array();
        for (const auto &stream : value.streams) {
            Json row={{"node",stream.node}};
            if (stream.logical_size) row["logicalSize"]={stream.logical_size->first,stream.logical_size->second};
            if (stream.position) row["position"]={stream.position->first,stream.position->second};
            streams.push_back(std::move(row));
        }
        bool ready=value.state==Session::State::Granted && selected.has_value() &&
            (value.input_method==Session::InputMethod::PortalDbus ||
             (eis && eis->snapshot().state==EisInput::State::Ready));
        Json result={{"state",session_name(value.state)},{"error",terminal_error.empty()?value.error:terminal_error},
            {"granted",value.state==Session::State::Granted},{"inputReady",ready && !stopping && !cleanup_pending},
            {"inputMethod",value.input_method==Session::InputMethod::Eis ? "eis" :
                value.input_method==Session::InputMethod::PortalDbus ? "portal-dbus" : "undetermined"},
            {"streams",streams},{"selectedStream",selected ? Json(*selected) : Json(nullptr)},
            {"grantedDevices",value.granted_devices},{"availableDevices",value.devices},{"availableSources",value.sources},
            {"cursorModes",value.cursor_modes ? Json(*value.cursor_modes) : Json(nullptr)},
            {"stopping",stopping}};
        if (capture) {
            auto state=capture->snapshot();
            result["capture"]={{"state",static_cast<int>(state.state)},{"width",state.width},{"height",state.height},
                {"frameSocket",state.socket_path},{"frames",state.frames},{"error",state.error}};
        } else result["capture"]=nullptr;
        return result;
    }
    void publish_state() {
        auto current=snapshot();
        auto material=current;
        if (material["capture"].is_object()) material["capture"].erase("frames");
        if (material!=published_material) {
            published_material=std::move(material);
            reply(nullptr,{{"event","state"},{"snapshot",std::move(current)}});
        }
    }
    void activity() {last_input=Clock::now();idle_release=last_input+std::chrono::seconds(3);}
    Session::Stream stream() const {
        auto value=session.snapshot();
        if (stopping || value.state!=Session::State::Granted || !selected || *selected>=value.streams.size())
            throw std::runtime_error("No selected desktop grant");
        return value.streams[*selected];
    }
    std::future<void> submit(const Session::Input &input) {
        return eis ? eis->submit(input) : session.notify_input(input);
    }
    void release(const Json &id,const std::string &error={}) {
        Work work{id,{},true,error};
        if (eis) work.operations.push_back(eis->release_held());
        else if (session.snapshot().state==Session::State::Granted) {
            for (auto code : keys) {
                Session::Input input{};input.kind=Session::Input::Kind::KeyboardKeycode;input.code=code;
                work.operations.push_back(session.notify_input(input));
            }
            for (auto code : buttons) {
                Session::Input input{};input.kind=Session::Input::Kind::PointerButton;input.code=code;
                work.operations.push_back(session.notify_input(input));
            }
        }
        keys.clear();buttons.clear();cleanup_pending=true;
        pending.push_back(std::move(work));
    }
    void end(const std::string &error={}) {
        if (stopping) return;
        stopping=true;terminal_error=error;
        // EIS performs its owned releases/frame before closing its consumer.
        // PortalSession flushes releases for dispatched legacy holds before
        // closing its private bus owner; compositor destruction alone does
        // not release those holds on every supported older desktop.
        if (eis) {
            eis->stop();
            // Consumer EOF can wake the portal before the EIS worker publishes
            // its final failure. Join that worker before choosing the reason.
            auto input=eis->snapshot();
            if (terminal_error.empty() && input.state==EisInput::State::Failed)
                terminal_error=input.error;
        }
        session.stop();
        auto stopped=session.snapshot();
        if (terminal_error.empty() && !stopped.error.empty()) terminal_error=stopped.error;
        if (capture) capture->stop();
        keys.clear();buttons.clear();
    }
    void event(const Json &id,const Json &value) {
        auto type=value.at("type").get<std::string>();
        if (type=="heartbeat") {activity();reply(id,{{"ok",true}});return;}
        if (type=="release") {activity();release(id);return;}
        if (cleanup_pending) throw std::runtime_error("Input release pending");
        auto granted=stream();
        if (eis && eis->snapshot().state!=EisInput::State::Ready)
            throw std::runtime_error("Desktop input unavailable");
        Session::Input input{};
        std::set<int> *held=nullptr;
        if (type=="key") {
            auto position=physical_key(value.at("code").get<std::string>());
            if (!position || !value.at("down").is_boolean()) throw std::runtime_error("Unsupported key");
            input.kind=Session::Input::Kind::KeyboardKeycode;input.code=position->evdev_code;
            input.down=value.at("down").get<bool>();held=&keys;
        } else if (type=="button") {
            if (!value.at("button").is_number_integer() || !value.at("down").is_boolean())
                throw std::runtime_error("Invalid button");
            int button=static_cast<int>(integer(value.at("button"),0,2));
            // Chrome left/middle/right -> Linux left/middle/right.
            static const int codes[]={BTN_LEFT,BTN_MIDDLE,BTN_RIGHT};
            input.kind=Session::Input::Kind::PointerButton;input.code=codes[button];
            input.down=value.at("down").get<bool>();held=&buttons;
        } else if (type=="move") {
            double x=value.at("x").get<double>(),y=value.at("y").get<double>();
            if (!std::isfinite(x) || !std::isfinite(y) || x<0 || x>1 || y<0 || y>1 ||
                !granted.logical_size || granted.logical_size->first<=0 || granted.logical_size->second<=0)
                throw std::runtime_error("Invalid coordinates or missing logical geometry");
            input.kind=Session::Input::Kind::PointerAbsolute;input.stream=granted.node;
            input.x=x*(granted.logical_size->first-1);input.y=y*(granted.logical_size->second-1);
        } else if (type=="wheel") {
            auto axis=value.at("axis").get<std::string>();
            if (!value.at("direction").is_number_integer()) throw std::runtime_error("Invalid scroll");
            int direction=static_cast<int>(integer(value.at("direction"),-1,1));
            if ((axis!="x" && axis!="y") || direction==0)
                throw std::runtime_error("Invalid scroll");
            input.kind=Session::Input::Kind::PointerAxisDiscrete;input.code=axis=="y"?0:1;input.steps=direction;
        } else throw std::runtime_error("Invalid input type");
        activity();
        // EIS owns per-device holds and clears pause debt on resume. Its
        // ownership cannot be inferred from this controller's admission set.
        if (held && !eis && (input.down ? held->count(input.code)!=0 : held->count(input.code)==0)) {
            reply(id,{{"ok",true}});return;
        }
        auto future=submit(input);
        if (held) {if (input.down) held->insert(input.code);else held->erase(input.code);}
        Work work{id,{},false,{}};
        work.idempotent_edge=held && bool(eis);
        work.operations.push_back(std::move(future));pending.push_back(std::move(work));
    }
    void command(const Json &value) {
        Json id=value.is_object() && value.contains("id") ? value["id"] : Json(nullptr);
        try {
            if (!value.is_object() || !value.contains("schemaVersion") ||
                !value["schemaVersion"].is_number_integer() || value["schemaVersion"]!=1 || !id.is_number_integer())
                throw std::runtime_error("Invalid guardian request");
            auto op=value.at("op").get<std::string>();
            if (op=="stop") {end();reply(id,{{"ok",true},{"snapshot",snapshot()}});}
            else if (op=="snapshot") reply(id,{{"ok",true},{"snapshot",snapshot()}});
            else if (op=="request") {
                const auto &request=value.at("request");
                if (!request.at("multiple").is_boolean()) throw std::runtime_error("Invalid desktop request");
                auto number=[&](const char *key) {
                    return static_cast<std::uint32_t>(integer(request.at(key),0,std::numeric_limits<std::uint32_t>::max()));
                };
                auto devices=number("devices");
                if (!devices || (devices&~3u)) throw std::runtime_error("Unsupported desktop input devices");
                bool accepted=session.request({devices,number("sourceTypes"),number("cursorMode"),
                    request.at("multiple").get<bool>(),request.at("parentWindow").get<std::string>()});
                if (!accepted) throw std::runtime_error("Desktop request unavailable or invalid");
                reply(id,{{"ok",true}});
            } else if (op=="select-stream") {
                if (selected) throw std::runtime_error("Desktop stream already selected");
                auto state=session.snapshot();
                if (!value.at("index").is_number_unsigned() && !value.at("index").is_number_integer())
                    throw std::runtime_error("Invalid stream index");
                auto index=value.at("index").get<std::int64_t>();
                if (state.state!=Session::State::Granted || index<0 || std::uint64_t(index)>=state.streams.size())
                    throw std::runtime_error("Selected stream not granted");
                selected=static_cast<std::size_t>(index);
                if (state.input_method==Session::InputMethod::Eis)
                    eis=std::make_unique<EisInput>(session.take_eis_connection(),state.granted_devices,state.streams[*selected]);
                reply(id,{{"ok",true},{"snapshot",snapshot()}});
            } else if (op=="capture-start") {
                auto granted=stream();
                if (capture || starting_capture) throw std::runtime_error("Capture already started");
                PipeWireCapture::Options options{value.at("runtimeDirectory").get<std::string>(),value.at("outputCaps").get<std::string>()};
                PipeWireCapture::validate(options);
                starting_capture.emplace(CaptureStart{id,session.open_pipewire_connection(),granted,std::move(options)});
            } else if (op=="capture-stop") {
                if (starting_capture) {
                    reply(starting_capture->id,{{"ok",false},{"error","Capture start cancelled"}});
                    starting_capture.reset();
                }
                if (capture_response) {
                    reply(*capture_response,{{"ok",false},{"error","Capture start cancelled"}});
                    capture_response.reset();
                }
                if (capture) {capture->stop();capture.reset();}
                reply(id,{{"ok",true}});
            } else if (op=="input") event(id,value.at("event"));
            else if (op=="release") {activity();release(id);}
            else throw std::runtime_error("Unknown guardian operation");
        } catch (const std::exception &error) {
            if (!keys.empty() || !buttons.empty()) release(id,error.what());
            else reply(id,{{"ok",false},{"error",error.what()}});
        }
    }
    void completions() {
        if (starting_capture && starting_capture->connection.wait_for(std::chrono::seconds(0))==std::future_status::ready) {
            auto start=std::move(*starting_capture);starting_capture.reset();
            try {
                auto connection=start.connection.get();
                if (stopping) throw std::runtime_error("Guardian stopped");
                capture=std::make_unique<PipeWireCapture>(std::move(connection),start.stream,std::move(start.options));
                capture_response=start.id;
            } catch (const std::exception &error) {reply(start.id,{{"ok",false},{"error",error.what()}});}
        }
        if (capture && capture_response) {
            auto state=capture->snapshot();
            if (state.state==PipeWireCapture::State::Streaming) {
                reply(*capture_response,{{"ok",true},{"snapshot",snapshot()}});capture_response.reset();
            } else if (state.state==PipeWireCapture::State::Failed || state.state==PipeWireCapture::State::Revoked || state.state==PipeWireCapture::State::Stopped) {
                reply(*capture_response,{{"ok",false},{"error",state.error.empty()?"Capture ended":state.error}});capture_response.reset();
            }
        }
        auto count=pending.size();
        while (count--) {
            Work work=std::move(pending.front());pending.pop_front();
            bool ready=std::all_of(work.operations.begin(),work.operations.end(),[](auto &future) {
                return future.wait_for(std::chrono::seconds(0))==std::future_status::ready;
            });
            if (!ready) {pending.push_back(std::move(work));continue;}
            std::string failure;
            for (auto &future : work.operations) {
                try {future.get();}
                catch (const Session::ConnectionError &error) {
                    // Supported DOM edges have already passed validation.
                    // EIS rejects duplicate presses/unowned releases without
                    // dispatch; retain the existing worker's idempotent edges.
                    if (!(work.idempotent_edge && error.failure==Session::Failure::InvalidInput) && failure.empty())
                        failure=error.what();
                }
                catch (const std::exception &error) {if (failure.empty()) failure=error.what();}
            }
            if (work.release) {
                cleanup_pending=std::any_of(pending.begin(),pending.end(),[](const Work &item) {return item.release;});
                if (!failure.empty()) end(failure);
                if (!work.id.is_null() || !work.error.empty()) reply(work.id,work.error.empty() && failure.empty() ? Json{{"ok",true}} :
                    Json{{"ok",false},{"error",work.error.empty()?failure:work.error}});
            } else if (!failure.empty() && !stopping) {
                // Native uncertainty first settles an owned-release barrier.
                // Its failure revokes the grant rather than replaying input.
                release(work.id,failure);
            } else reply(work.id,failure.empty()?Json{{"ok",true}}:Json{{"ok",false},{"error",failure}});
        }
    }
    void flush() {
        while (sent<outgoing.size()) {
            auto count=send(control,outgoing.data()+sent,outgoing.size()-sent,MSG_NOSIGNAL|MSG_DONTWAIT);
            if (count>0) {sent+=static_cast<std::size_t>(count);continue;}
            if (count<0 && errno==EINTR) continue;
            if (count<0 && (errno==EAGAIN || errno==EWOULDBLOCK)) return;
            end();return;
        }
        outgoing.clear();sent=0;
    }
  public:
    explicit Guardian(int descriptor):control(descriptor) {}
    ~Guardian() {end();}
    int run() {
        reply(nullptr,{{"event","started"},{"pid",getpid()},{"ok",true}});
        for (;;) {
            completions();
            auto state=session.snapshot();
            if (!stopping && (state.state==Session::State::Failed || state.state==Session::State::Closed ||
                state.state==Session::State::NotGranted || state.state==Session::State::Stopped)) end(state.error);
            if (!stopping && eis) {
                auto input=eis->snapshot();
                if (input.state==EisInput::State::Failed || input.state==EisInput::State::Revoked || input.state==EisInput::State::Stopped)
                    end(input.error);
            }
            if (!stopping && capture) {
                auto current=capture->snapshot();
                if (current.state==PipeWireCapture::State::Failed || current.state==PipeWireCapture::State::Revoked) end(current.error);
            }
            if (stopping) {
                completions();
                publish_state();
                reply(nullptr,{{"event","ended"},{"snapshot",snapshot()}});
                flush();
                return terminal_error.empty()?0:1;
            }
            auto now=Clock::now();
            if (now>=idle_release) {
                if ((!keys.empty() || !buttons.empty()) && !cleanup_pending) release(nullptr);
                idle_release=now+std::chrono::seconds(3);
                completions();
            }
            publish_state();
            flush();
            if (stopping) continue;
            std::vector<pollfd> items{{control,short(POLLIN|(sent<outgoing.size()?POLLOUT:0)),0},
                {signals.pipe[0],POLLIN,0},{session.state_descriptor(),POLLIN,0}};
            if (eis) items.push_back({eis->state_descriptor(),POLLIN,0});
            if (capture) items.push_back({capture->state_descriptor(),POLLIN,0});
            auto remaining=std::chrono::duration_cast<std::chrono::milliseconds>(idle_release-Clock::now()).count();
            int result=poll(items.data(),items.size(),static_cast<int>(std::max<std::int64_t>(0,remaining)));
            if (result<0) {if (errno==EINTR) continue;throw std::runtime_error("Guardian poll failed");}
            if (items[1].revents) {end();continue;}
            for (std::size_t index=2;index<items.size();++index) if (items[index].revents) drain(items[index].fd);
            if (items[0].revents&(POLLERR|POLLNVAL)) {end();continue;}
            if (items[0].revents&(POLLIN|POLLHUP)) {
                char bytes[8192];
                auto count=recv(control,bytes,sizeof(bytes),MSG_DONTWAIT);
                if (count==0) {end();continue;}
                if (count<0) {if (errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR) continue;end();continue;}
                incoming.append(bytes,static_cast<std::size_t>(count));
                for (std::size_t newline;!stopping && (newline=incoming.find('\n'))!=std::string::npos;) {
                    auto line=incoming.substr(0,newline);incoming.erase(0,newline+1);
                    try {command(Json::parse(line));}
                    catch (const std::exception &error) {release(nullptr,error.what());}
                }
            }
        }
    }
};
}
int wayland_guardian_worker(int controller,pid_t parent) {
    try {verify_controller(controller,parent);Guardian guardian(controller);return guardian.run();}
    catch (const std::exception &error) {std::cerr<<"Wayland guardian: "<<error.what()<<'\n';return 1;}
}
}
