#include "eis_input.hpp"
#include "notification_probe.hpp"
#include "input_keys.hpp"
#include <nlohmann/json.hpp>
#include <chrono>
#include <fcntl.h>
#include <iostream>
#include <map>
#include <poll.h>
#include <thread>
#include <sys/socket.h>
#include <unistd.h>
namespace {
using Json=nlohmann::json;
using Session=traverse::PortalSession;
using Sender=traverse::EisInput;
const char *name(Sender::State state) {
    switch (state) {
    case Sender::State::Starting:return "starting";
    case Sender::State::Ready:return "ready";
    case Sender::State::Unavailable:return "unavailable";
    case Sender::State::Revoked:return "revoked";
    case Sender::State::Failed:return "failed";
    case Sender::State::Stopped:return "stopped";
    }
    return "unknown";
}
Session::Snapshot wait(Session &session,bool grant) {
    auto end=std::chrono::steady_clock::now()+std::chrono::seconds(5);
    for (;;) {
        auto state=session.snapshot();
        if (state.state == Session::State::Failed || state.state == Session::State::Stopped ||
            state.state == Session::State::NotGranted || state.state == Session::State::Closed ||
            state.state == (grant ? Session::State::Granted : Session::State::CapabilitiesReady)) return state;
        if (std::chrono::steady_clock::now() >= end) throw std::runtime_error("Portal test watchdog expired");
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}
void wait_ready(Sender &sender) {
    auto end=std::chrono::steady_clock::now()+std::chrono::seconds(5);
    for (;;) {
        auto state=sender.snapshot().state;
        if (state == Sender::State::Ready || state == Sender::State::Failed || state == Sender::State::Stopped || state == Sender::State::Revoked) return;
        int remaining=int(std::chrono::duration_cast<std::chrono::milliseconds>(end-std::chrono::steady_clock::now()).count());
        if (remaining <= 0) return;
        pollfd notification{sender.state_descriptor(),POLLIN,0};
        if (poll(&notification,1,remaining) > 0) { char bytes[128]; while (read(notification.fd,bytes,sizeof(bytes)) > 0) {} }
    }
}
}
int main(int argc,char **argv) {
    try {
        bool small_buffer=argc == 2 && std::string(argv[1]) == "--small-send-buffer";
        bool desktop=argc == 2 && std::string(argv[1]) == "--desktop";
        if (argc != 1 && !small_buffer && !desktop) throw std::runtime_error("Unknown sender probe option");
        Session session;
        if (wait(session,false).state != Session::State::CapabilitiesReady || !session.request({3,1,2,false,""}))
            throw std::runtime_error("Test grant unavailable");
        Session::Snapshot grant;
        Session::Connection capture;
        std::unique_ptr<Sender> sender;
        int watched=-1;
        auto begin=[&] {
            grant=session.snapshot();
            if (grant.state != Session::State::Granted || grant.input_method != Session::InputMethod::Eis || grant.streams.size() != 1)
                throw std::runtime_error("Test EIS grant missing");
            capture=session.open_pipewire_connection().get();
            auto lease=session.take_eis_connection();
            watched=lease.descriptor();
            if (small_buffer) {
                int requested=1024; // controlled fault fixture only, no app default
                if (setsockopt(watched,SOL_SOCKET,SO_SNDBUF,&requested,sizeof(requested)))
                    throw std::runtime_error("Test socket buffer configuration failed");
            }
            sender=std::make_unique<Sender>(std::move(lease),grant.granted_devices,grant.streams.front());
        };
        if (desktop) std::cout << Json{{"permissionRequested",true}} << std::endl;
        else { wait(session,true); begin(); std::cout << Json{{"constructed",true}} << std::endl; }
        std::map<int,std::future<void>> results;
        int identifier=0;
        std::string line;
        while (std::getline(std::cin,line)) {
            auto command=Json::parse(line); std::string op=command.at("op"); Json response;
            if (op == "permission" && desktop) {
                auto current=session.snapshot();
                if (!sender && current.state == Session::State::Granted) begin();
                Json streams=Json::array();
                for (const auto &stream : current.streams) {
                    Json row={{"node",stream.node}};
                    if (stream.logical_size) row["size"]={stream.logical_size->first,stream.logical_size->second};
                    if (stream.position) row["position"]={stream.position->first,stream.position->second};
                    if (stream.mapping_id) row["mappingId"]=*stream.mapping_id;
                    streams.push_back(row);
                }
                response={{"constructed",bool(sender)},{"granted",current.state == Session::State::Granted},
                    {"waitingPermission",current.state == Session::State::WaitingPermission},{"error",current.error},
                    {"inputMethod",current.input_method == Session::InputMethod::Eis ? "eis" : "undetermined-or-legacy"},
                    {"streams",streams},{"grantedDevices",current.granted_devices}};
            } else if (!sender) {
                if (op == "stop" || op == "quit") session.stop();
                response={{"stopped",session.snapshot().state == Session::State::Stopped},{"constructed",false}};
                std::cout << response << std::endl;
                if (op == "quit") return 0;
                continue;
            } else if (op == "notify-key") {
                drain_notification(sender->state_descriptor());
                Session::Input input{};
                input.kind=Session::Input::Kind::KeyboardKeycode;
                input.code=command.value("code",30);input.down=command.value("down",true);
                auto future=sender->submit(input);
                notified_future(sender->state_descriptor(),future);
                response={{"completionNotified",true}};
                try { future.get();response["delivered"]=true; }
                catch (const Session::ConnectionError &) {response["delivered"]=false;}
            } else if (op == "state" || op == "ready") {
                if (op == "ready") wait_ready(*sender);
                auto state=sender->snapshot();
                response={{"state",name(state.state)},{"error",state.error},{"devices",state.devices},{"resumed",state.resumed_devices}};
            } else if (op == "input" || op == "release") {
                std::future<void> result;
                if (op == "release") result=sender->release_held();
                else {
                    Session::Input input{}; std::string kind=command.at("kind");
                    if (kind == "absolute") input.kind=Session::Input::Kind::PointerAbsolute;
                    else if (kind == "button") input.kind=Session::Input::Kind::PointerButton;
                    else if (kind == "scroll") input.kind=Session::Input::Kind::PointerAxisDiscrete;
                    else if (kind == "key") input.kind=Session::Input::Kind::KeyboardKeycode;
                    else if (kind == "dom-key") input.kind=Session::Input::Kind::KeyboardKeycode;
                    else if (kind == "keysym") input.kind=Session::Input::Kind::KeyboardKeysym;
                    else throw std::runtime_error("Unknown test input");
                    input.stream=command.value("stream",grant.streams.front().node);
                    input.x=command.value("x",0.0); input.y=command.value("y",0.0);
                    if (kind == "dom-key") {
                        auto position=traverse::physical_key(command.at("code").get<std::string>());
                        input.code=position ? position->evdev_code : -1;
                    } else input.code=command.value("code",0);
                    input.steps=command.value("steps",0); input.down=command.value("down",false);
                    result=sender->submit(input);
                }
                results.emplace(++identifier,std::move(result)); response={{"id",identifier}};
            } else if (op == "result") {
                int id=command.at("id"); auto &future=results.at(id);
                bool ready=future.wait_for(command.value("wait",false) ? std::chrono::seconds(5) : std::chrono::seconds(0)) == std::future_status::ready;
                response={{"ready",ready}};
                if (ready) {
                    try { future.get(); response["delivered"]=true; }
                    catch (const Session::ConnectionError &error) { response["delivered"]=false; response["failure"]=int(error.failure); }
                    results.erase(id);
                }
            } else if (op == "writable" && small_buffer) {
                // Passive poll only, while the controlled peer remains alive;
                // never a second protocol reader or an extra owning duplicate.
                pollfd socket{watched,POLLOUT,0};
                int ready=poll(&socket,1,0);
                response={{"writable",ready > 0 && bool(socket.revents & POLLOUT)},
                          {"descriptorValid",fcntl(watched,F_GETFD) >= 0}};
            } else if (op == "stop") { sender->stop(); response={{"state",name(sender->snapshot().state)}}; }
            else if (op == "grant") {
                auto snapshot=session.snapshot();
                response={{"granted",snapshot.state == Session::State::Granted},{"stopped",snapshot.state == Session::State::Stopped},
                    {"captureValid",capture.valid()},{"captureDescriptorHeld",fcntl(capture.descriptor(),F_GETFD) >= 0}};
            } else if (op == "quit") {
                sender->stop(); session.stop();
                bool settled=true;
                for (auto &[_,future] : results) settled=settled && future.wait_for(std::chrono::seconds(0)) == std::future_status::ready;
                response={{"allResultsSettled",settled},{"captureRevoked",!capture.valid()}};
                std::cout << response << std::endl;
                return settled && !capture.valid() ? 0 : 1;
            } else throw std::runtime_error("Unknown sender test command");
            std::cout << response << std::endl;
        }
        if (sender) sender->stop();
        session.stop();
        return 0;
    } catch (const std::exception &error) { std::cerr << error.what() << '\n'; return 1; }
}
