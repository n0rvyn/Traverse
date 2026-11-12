#include <libeis.h>
#include <nlohmann/json.hpp>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <map>
#include <memory>
#include <poll.h>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
namespace {
using Json=nlohmann::json;
template<class T, auto Unref> struct Drop { void operator()(T *p) const { if (p) Unref(p); } };
template<class T, auto Unref> using Owned=std::unique_ptr<T,Drop<T,Unref>>;
void output(Json value) { std::cout << value << std::endl; }
eis_device_capability capability(const std::string &name) {
    if (name == "absolute") return EIS_DEVICE_CAP_POINTER_ABSOLUTE;
    if (name == "keyboard") return EIS_DEVICE_CAP_KEYBOARD;
    if (name == "button") return EIS_DEVICE_CAP_BUTTON;
    if (name == "scroll") return EIS_DEVICE_CAP_SCROLL;
    throw std::runtime_error("Unknown test capability");
}
void send_client(int control,int fd) {
    char byte='E'; iovec vector{&byte,1};
    alignas(cmsghdr) char ancillary[CMSG_SPACE(sizeof(int))]{};
    msghdr message{}; message.msg_iov=&vector; message.msg_iovlen=1;
    message.msg_control=ancillary; message.msg_controllen=sizeof(ancillary);
    auto *header=CMSG_FIRSTHDR(&message);
    header->cmsg_level=SOL_SOCKET; header->cmsg_type=SCM_RIGHTS; header->cmsg_len=CMSG_LEN(sizeof(int));
    std::memcpy(CMSG_DATA(header),&fd,sizeof(fd));
    if (sendmsg(control,&message,MSG_NOSIGNAL) != 1) throw std::runtime_error("Client FD handoff failed");
}
}
// Test-only process. Only the separate control socket is inherited. libeis
// creates the actual client endpoint; SCM_RIGHTS transfers it to the portal.
int eis_test_server(int control) {
    std::string line;
    if (!std::getline(std::cin,line)) throw std::runtime_error("Missing server configuration");
    Json config=Json::parse(line);
    Owned<eis,eis_unref> server(eis_new(nullptr));
    if (!server || eis_setup_backend_fd(server.get())) throw std::runtime_error("Test EIS backend unavailable");
    int fd=eis_backend_fd_add_client(server.get());
    if (fd < 0) throw std::runtime_error("Test EIS socket unavailable");
    try { send_client(control,fd); } catch (...) { close(fd); close(control); throw; }
    close(fd); close(control);
    std::map<std::size_t,Owned<eis_device,eis_device_unref>> devices;
    Owned<eis_client,eis_client_unref> client;
    Owned<eis_seat,eis_seat_unref> seat;
    bool held=false, running=true;
    int flags=fcntl(STDIN_FILENO,F_GETFL);
    if (flags < 0 || fcntl(STDIN_FILENO,F_SETFL,flags|O_NONBLOCK)) throw std::runtime_error("Test control flags failed");
    std::string input;
    output({{"serverReady",true}});
    while (running) {
        if (!held) {
            eis_dispatch(server.get());
            while (auto *raw=eis_get_event(server.get())) {
                Owned<eis_event,eis_event_unref> event(raw);
                Json record;
                switch (eis_event_get_type(raw)) {
                case EIS_EVENT_CLIENT_CONNECT: {
                    client.reset(eis_client_ref(eis_event_get_client(raw)));
                    if (config.value("withhold",false)) { output({{"event","withheld"}}); break; }
                    eis_client_connect(client.get());
                    seat.reset(eis_client_new_seat(client.get(),"controlled"));
                    for (auto cap : {EIS_DEVICE_CAP_POINTER_ABSOLUTE,EIS_DEVICE_CAP_KEYBOARD,EIS_DEVICE_CAP_BUTTON,EIS_DEVICE_CAP_SCROLL})
                        eis_seat_configure_capability(seat.get(),cap);
                    eis_seat_add(seat.get());
                    output({{"event","connected"}}); break;
                }
                case EIS_EVENT_SEAT_BIND: {
                    std::size_t index=0;
                    for (const auto &spec : config.at("devices")) {
                        bool permitted=true;
                        for (const auto &name : spec.at("caps"))
                            permitted=permitted && eis_event_seat_has_capability(raw,capability(name.get<std::string>()));
                        if (permitted && !devices.count(index)) {
                            Owned<eis_device,eis_device_unref> device(eis_seat_new_device(eis_event_get_seat(raw)));
                            auto name="controlled-"+std::to_string(index);
                            eis_device_configure_name(device.get(),name.c_str());
                            for (const auto &cap : spec.at("caps")) eis_device_configure_capability(device.get(),capability(cap.get<std::string>()));
                            for (const auto &r : spec.value("regions",Json::array())) {
                                Owned<eis_region,eis_region_unref> region(eis_device_new_region(device.get()));
                                eis_region_set_size(region.get(),r.at("width").get<std::uint32_t>(),r.at("height").get<std::uint32_t>());
                                eis_region_set_offset(region.get(),r.value("x",0u),r.value("y",0u));
                                if (r.contains("id")) eis_region_set_mapping_id(region.get(),r.at("id").get<std::string>().c_str());
                                eis_region_set_physical_scale(region.get(),r.value("scale",1.0));
                                eis_region_add(region.get());
                            }
                            eis_device_add(device.get());
                            if (spec.value("resume",true)) eis_device_resume(device.get());
                            devices.emplace(index,std::move(device));
                        }
                        ++index;
                    }
                    break;
                }
                case EIS_EVENT_POINTER_MOTION_ABSOLUTE:
                    record={{"event","absolute"},{"x",eis_event_pointer_get_absolute_x(raw)},{"y",eis_event_pointer_get_absolute_y(raw)}}; break;
                case EIS_EVENT_BUTTON_BUTTON:
                    record={{"event","button"},{"code",eis_event_button_get_button(raw)},{"down",eis_event_button_get_is_press(raw)}}; break;
                case EIS_EVENT_KEYBOARD_KEY:
                    record={{"event","key"},{"code",eis_event_keyboard_get_key(raw)},{"down",eis_event_keyboard_get_key_is_press(raw)}}; break;
                case EIS_EVENT_SCROLL_DISCRETE:
                    record={{"event","scroll"},{"x",eis_event_scroll_get_discrete_dx(raw)},{"y",eis_event_scroll_get_discrete_dy(raw)}}; break;
                case EIS_EVENT_SCROLL_DELTA: record={{"event","pixel-scroll"}}; break;
                case EIS_EVENT_FRAME: record={{"event","frame"}}; break;
                case EIS_EVENT_DEVICE_START_EMULATING: record={{"event","start"}}; break;
                case EIS_EVENT_DEVICE_STOP_EMULATING: record={{"event","stop"}}; break;
                case EIS_EVENT_CLIENT_DISCONNECT:
                    record={{"event","disconnect"}};
                    eis_client_disconnect(eis_event_get_client(raw)); break;
                default: break;
                }
                if (!record.is_null()) {
                    auto *device=eis_event_get_device(raw);
                    if (device) record["device"]=eis_device_get_name(device);
                    output(record);
                }
            }
        }
        pollfd fds[]={{held ? -1 : eis_get_fd(server.get()),POLLIN,0},{STDIN_FILENO,POLLIN|POLLHUP,0}};
        int ready=poll(fds,2,-1);
        if (ready < 0) { if (errno == EINTR) continue; throw std::runtime_error("Test server poll failed"); }
        if (fds[1].revents) {
            char bytes[4096]; ssize_t count;
            while ((count=read(STDIN_FILENO,bytes,sizeof(bytes))) > 0) input.append(bytes,std::size_t(count));
            if (count == 0) running=false;
            else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) throw std::runtime_error("Test server control read failed");
            for (auto end=input.find('\n'); end != std::string::npos; end=input.find('\n')) {
                auto command=Json::parse(input.substr(0,end)); input.erase(0,end+1);
                std::string op=command.at("op");
                if (op == "hold") held=true;
                else if (op == "dispatch") held=false;
                else if (op == "disconnect") { if (client) eis_client_disconnect(client.get()); held=false; }
                else if (op == "remove-seat") { if (seat) eis_seat_remove(seat.get()); }
                else if (op == "quit") running=false;
                else if (op == "pending") {
                    // Passive readiness only: do not consume protocol bytes.
                    pollfd pending{eis_get_fd(server.get()),POLLIN,0};
                    int available=poll(&pending,1,0);
                    if (available<0) throw std::runtime_error("Pending wire observation failed");
                    output({{"command",op},{"pending",available>0 && bool(pending.revents&POLLIN)}});
                    continue;
                }
                else {
                    auto &device=devices.at(command.value("device",std::size_t(0)));
                    if (op == "pause") eis_device_pause(device.get());
                    else if (op == "resume") eis_device_resume(device.get());
                    else if (op == "remove") eis_device_remove(device.get());
                    else throw std::runtime_error("Unknown server command");
                }
                output({{"command",op}});
            }
        }
    }
    return 0;
}
