#include "eis_input.hpp"
#include "change_notification.hpp"
#include "input_keys.hpp"
#include <libei.h>
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <deque>
#include <fcntl.h>
#include <limits>
#include <map>
#include <mutex>
#include <poll.h>
#include <set>
#include <thread>
#include <unistd.h>

namespace traverse {
namespace {
using Session = PortalSession;
void wake(int fd) noexcept {
    const char byte = 1;
    while (write(fd, &byte, 1) < 0 && errno == EINTR) {}
}
void drain(int fd) noexcept { char bytes[128]; while (read(fd, bytes, sizeof(bytes)) > 0) {} }
std::pair<float,float> wire_bounds(std::uint32_t offset,std::uint32_t extent) {
    double end=double(offset)+extent;
    float first=float(offset), last=float(end);
    if (double(first) < offset) first=std::nextafter(first,std::numeric_limits<float>::infinity());
    if (double(last) >= end) last=std::nextafter(last,-std::numeric_limits<float>::infinity());
    return {first,last};
}
bool usable_region(ei_region *region) {
    if (!(ei_region_get_width(region) && ei_region_get_height(region) &&
        std::uint64_t(ei_region_get_x(region)) + ei_region_get_width(region) <= std::numeric_limits<std::uint32_t>::max() &&
        std::uint64_t(ei_region_get_y(region)) + ei_region_get_height(region) <= std::numeric_limits<std::uint32_t>::max())) return false;
    auto x=wire_bounds(ei_region_get_x(region),ei_region_get_width(region));
    auto y=wire_bounds(ei_region_get_y(region),ei_region_get_height(region));
    return x.first <= x.second && y.first <= y.second;
}
double wire_coordinate(std::uint32_t offset,std::uint32_t extent,double value,std::int32_t logical_extent) {
    auto bounds=wire_bounds(offset,extent);
    // The protocol scanner encodes coordinates as float32, although the public
    // API accepts double. Keep the encoded value inside the half-open region.
    float coordinate=float(double(offset)+value*extent/logical_extent);
    return std::clamp(coordinate,bounds.first,bounds.second);
}
}
struct EisInput::Impl {
    Session::Connection connection;
    const std::uint32_t granted;
    const Session::Stream stream;
    mutable std::mutex mutex;
    std::mutex stop_mutex;
    Snapshot value;
    std::atomic<bool> stopping{false};
    int command[2]{-1,-1};
    ChangeNotification changed;
    std::thread worker;
    ei *context = nullptr; // worker only
    std::uint32_t sequence = 0;
    std::string termination_reason;
    struct Device {
        ei_device *handle;
        bool resumed = false, emulating = false;
        std::set<std::int32_t> keys, buttons;
    };
    std::map<ei_device *, Device> devices;
    std::set<ei_seat *> seats;
    struct Selection { Device *pointer=nullptr, *button=nullptr, *scroll=nullptr, *keyboard=nullptr; ei_region *region=nullptr; } selected;
    struct Request {
        bool release = false;
        Session::Input input{};
        std::promise<void> promise;
    };
    std::deque<std::shared_ptr<Request>> queued;
    std::map<struct ei_ping *, std::shared_ptr<Request>> waiting;

    Impl(Session::Connection lease, std::uint32_t mask, Session::Stream source)
        : connection(std::move(lease)), granted(mask), stream(std::move(source)) {
        if (!connection.valid() || connection.protocol() != Session::Connection::Protocol::Eis || !granted ||
            (granted & ~3u) || !stream.node || stream.node == std::numeric_limits<std::uint32_t>::max() ||
            ((granted & 2u) && (!stream.logical_size || stream.logical_size->first <= 0 || stream.logical_size->second <= 0)))
            throw std::invalid_argument("A current EIS grant and selected logical stream are required");
        if (pipe2(command, O_CLOEXEC | O_NONBLOCK)) throw std::runtime_error("EIS command channel unavailable");
        try { worker = std::thread([this] { run(); }); }
        catch (...) { for (int fd : {command[0],command[1]}) close(fd); throw; }
    }
    ~Impl() {
        stop();
        for (int fd : {command[0],command[1]}) close(fd);
    }
    void publish(State state, const std::string &error={}) {
        std::lock_guard lock(mutex);
        std::size_t resumed=0;
        for (const auto &[_,device] : devices) if (device.resumed) ++resumed;
        if (value.state != state || value.error != error || value.devices != devices.size() || value.resumed_devices != resumed) {
            value = {state,error,devices.size(),resumed}; changed.notify();
        }
    }
    void fail(const std::shared_ptr<Request> &request, Session::Failure reason, const char *message) {
        request->promise.set_exception(std::make_exception_ptr(Session::ConnectionError(reason,message)));
        changed.notify();
    }
    Session::Failure validate(const Session::Input &input) const {
        using Kind = Session::Input::Kind;
        switch (input.kind) {
        case Kind::PointerAbsolute:
            if (!(granted & 2u)) return Session::Failure::Unavailable;
            return input.stream == stream.node && valid_pointer_position(input.x,input.y,stream.logical_size->first,stream.logical_size->second)
                ? Session::Failure::None : Session::Failure::InvalidInput;
        case Kind::PointerButton:
            if (!(granted & 2u)) return Session::Failure::Unavailable;
            return valid_pointer_button(input.code) ? Session::Failure::None : Session::Failure::InvalidInput;
        case Kind::PointerAxisDiscrete:
            if (!(granted & 2u)) return Session::Failure::Unavailable;
            return valid_discrete_axis(input.code,input.steps) ? Session::Failure::None : Session::Failure::InvalidInput;
        case Kind::KeyboardKeycode:
            if (!(granted & 1u)) return Session::Failure::Unavailable;
            return valid_keyboard_keycode(input.code) ? Session::Failure::None : Session::Failure::InvalidInput;
        case Kind::KeyboardKeysym: return Session::Failure::InvalidInput;
        }
        return Session::Failure::InvalidInput;
    }
    std::future<void> submit(Session::Input input, bool release) {
        auto request=std::make_shared<Request>(); request->input=input; request->release=release;
        auto future=request->promise.get_future();
        std::lock_guard lock(mutex);
        auto reason=stopping ? Session::Failure::Cancelled : value.state != State::Ready ? Session::Failure::Unavailable :
            release ? Session::Failure::None : validate(input);
        if (reason != Session::Failure::None) fail(request,reason,"EIS input unavailable or invalid");
        else { queued.push_back(request); wake(command[1]); }
        return future;
    }
    void stop() {
        std::lock_guard stop_lock(stop_mutex);
        { std::lock_guard lock(mutex); stopping=true; wake(command[1]); }
        if (worker.joinable()) worker.join();
    }
    void clear_holds(Device &device) {
        if (device.keys.empty() && device.buttons.empty()) return;
        for (auto code : device.keys) ei_device_keyboard_key(device.handle,code,false);
        for (auto code : device.buttons) ei_device_button_button(device.handle,code,false);
        ei_device_frame(device.handle,ei_now(context));
        device.keys.clear(); device.buttons.clear();
    }
    bool match(ei_region *region, bool exact) const {
        if (!usable_region(region)) return false;
        const char *id=ei_region_get_mapping_id(region);
        bool stream_id=stream.mapping_id && !stream.mapping_id->empty();
        bool region_id=id && *id;
        if (exact) return stream_id && region_id && *stream.mapping_id == id;
        if (stream_id && region_id) return false;
        // Without mapping IDs, require unambiguous matching logical metadata.
        // Portal positions are signed; EIS1.5 offsets are unsigned. Negative
        // portal positions require an ID rather than an invented translation.
        if (ei_region_get_width(region) != std::uint32_t(stream.logical_size->first) ||
            ei_region_get_height(region) != std::uint32_t(stream.logical_size->second)) return false;
        return !stream.position || (stream.position->first >= 0 && stream.position->second >= 0 &&
            ei_region_get_x(region) == std::uint32_t(stream.position->first) &&
            ei_region_get_y(region) == std::uint32_t(stream.position->second));
    }
    void select() {
        selected={};
        ei_seat *seat=nullptr;
        if (granted & 2u) {
            unsigned matches=0;
            for (bool exact : {true,false}) {
                for (auto &[_,device] : devices) {
                    if (!device.resumed || !seats.count(ei_device_get_seat(device.handle)) ||
                        !ei_device_has_capability(device.handle,EI_DEVICE_CAP_POINTER_ABSOLUTE)) continue;
                    for (std::size_t i=0; auto *region=ei_device_get_region(device.handle,i); ++i) {
                        if (match(region,exact)) { ++matches; selected.pointer=&device; selected.region=region; }
                    }
                }
                if (matches) break; // exact identifiers outrank metadata-only matches
            }
            if (matches != 1) { selected={}; publish(State::Unavailable,"No unique granted EIS region"); return; }
            seat=ei_device_get_seat(selected.pointer->handle);
        }
        auto unique=[&](ei_device_capability cap) -> Device * {
            Device *result=nullptr;
            for (auto &[_,device] : devices) {
                if (!device.resumed || !seats.count(ei_device_get_seat(device.handle)) ||
                    (seat && ei_device_get_seat(device.handle) != seat) || !ei_device_has_capability(device.handle,cap)) continue;
                if (result) return nullptr;
                result=&device;
            }
            return result;
        };
        if (granted & 2u) { selected.button=unique(EI_DEVICE_CAP_BUTTON); selected.scroll=unique(EI_DEVICE_CAP_SCROLL); }
        if (granted & 1u) selected.keyboard=unique(EI_DEVICE_CAP_KEYBOARD);
        bool ready=(!(granted & 2u) || (selected.pointer && selected.button && selected.scroll)) &&
            (!(granted & 1u) || selected.keyboard);
        publish(ready ? State::Ready : State::Unavailable,ready ? "" : "Required EIS devices are unavailable or ambiguous");
    }
    bool events() {
        ei_dispatch(context);
        bool disconnected=false;
        std::set<struct ei_ping *> pongs;
        while (auto *event=ei_get_event(context)) {
            std::unique_ptr<ei_event,decltype(&ei_event_unref)> owned(event,ei_event_unref);
            auto *handle=ei_event_get_device(event);
            switch (ei_event_get_type(event)) {
            case EI_EVENT_DISCONNECT:
                disconnected=true;
                if (termination_reason.empty()) termination_reason="EIS peer disconnected";
                break;
            case EI_EVENT_PONG: pongs.insert(ei_event_pong_get_ping(event)); break;
            case EI_EVENT_SEAT_ADDED: {
                auto *seat=ei_event_get_seat(event);
                if (!seats.insert(ei_seat_ref(seat)).second) { ei_seat_unref(seat); break; }
                if (granted & 1u) ei_seat_bind_capabilities(seat,EI_DEVICE_CAP_KEYBOARD,nullptr);
                if (granted & 2u) ei_seat_bind_capabilities(seat,EI_DEVICE_CAP_POINTER_ABSOLUTE,EI_DEVICE_CAP_BUTTON,EI_DEVICE_CAP_SCROLL,nullptr);
                break;
            }
            case EI_EVENT_SEAT_REMOVED: {
                auto *seat=ei_event_get_seat(event);
                if (seats.erase(seat)) ei_seat_unref(seat);
                break;
            }
            case EI_EVENT_DEVICE_ADDED:
                if (!devices.count(handle)) devices.emplace(handle,Device{ei_device_ref(handle),false,false,{},{}});
                break;
            case EI_EVENT_DEVICE_RESUMED: {
                auto found=devices.find(handle);
                if (found == devices.end()) throw std::runtime_error("Unknown resumed EIS device");
                auto &device=found->second;
                device.resumed=true;
                if (!device.emulating) { ei_device_start_emulating(handle,++sequence); device.emulating=true; }
                clear_holds(device); // debt from pause, before publishing Ready
                break;
            }
            case EI_EVENT_DEVICE_PAUSED: {
                auto found=devices.find(handle);
                if (found != devices.end()) { found->second.resumed=false; found->second.emulating=false; }
                break;
            }
            case EI_EVENT_DEVICE_REMOVED: {
                auto found=devices.find(handle);
                if (found != devices.end()) {
                    if (!found->second.keys.empty() || !found->second.buttons.empty()) {
                        disconnected=true;
                        if (termination_reason.empty()) termination_reason="EIS device removed while owned input was held";
                    }
                    selected={}; ei_device_unref(handle); devices.erase(found);
                }
                break;
            }
            default: break;
            }
        }
        // libei fabricates pending PONGs on disconnect. None can acknowledge
        // delivery until the entire event batch has been checked for failure.
        if (disconnected) return false;
        {
            std::lock_guard lock(mutex);
            // The same admission lock defines Stop's cutoff. No still-pending
            // result can become successful after Stop wins that lock.
            if (!stopping && connection.valid()) for (auto *ping : pongs) {
                auto found=waiting.find(ping);
                if (found != waiting.end()) { found->second->promise.set_value(); changed.notify(); ei_ping_unref(ping); waiting.erase(found); }
            }
        }
        if (stopping) return true;
        select();
        return true;
    }
    void send(const std::shared_ptr<Request> &request) {
        // Caller holds admission mutex. Stop cannot cross a partial input send.
        if (stopping || !connection.valid() || value.state != State::Ready) {
            fail(request,stopping || !connection.valid() ? Session::Failure::Cancelled : Session::Failure::Unavailable,"EIS device no longer ready"); return;
        }
        if (request->release) {
            for (auto &[_,device] : devices) {
                if ((!device.keys.empty() || !device.buttons.empty()) && !device.resumed) {
                    fail(request,Session::Failure::Unavailable,"Held EIS device is paused"); return;
                }
            }
            for (auto &[_,device] : devices) clear_holds(device);
        } else {
            const auto &input=request->input;
            using Kind=Session::Input::Kind;
            Device *device=nullptr;
            switch (input.kind) {
            case Kind::PointerAbsolute: {
                device=selected.pointer;
                auto *region=selected.region;
                double x=wire_coordinate(ei_region_get_x(region),ei_region_get_width(region),input.x,stream.logical_size->first);
                double y=wire_coordinate(ei_region_get_y(region),ei_region_get_height(region),input.y,stream.logical_size->second);
                ei_device_pointer_motion_absolute(device->handle,x,y); break;
            }
            case Kind::PointerAxisDiscrete:
                device=selected.scroll;
                ei_device_scroll_discrete(device->handle,input.code == 1 ? input.steps*120 : 0,input.code == 0 ? input.steps*120 : 0); break;
            case Kind::PointerButton:
            case Kind::KeyboardKeycode: {
                bool keyboard=input.kind == Kind::KeyboardKeycode;
                device=keyboard ? selected.keyboard : selected.button;
                auto &holds=keyboard ? device->keys : device->buttons;
                if (holds.count(input.code) == (input.down ? 1u : 0u)) {
                    fail(request,Session::Failure::InvalidInput,"Duplicate EIS press or unowned release"); return;
                }
                if (keyboard) ei_device_keyboard_key(device->handle,input.code,input.down);
                else ei_device_button_button(device->handle,input.code,input.down);
                if (input.down) holds.insert(input.code); else holds.erase(input.code);
                break;
            }
            case Kind::KeyboardKeysym:
                fail(request,Session::Failure::InvalidInput,"EIS keysym input is unsupported"); return;
            }
            ei_device_frame(device->handle,ei_now(context));
        }
        auto *ping=ei_new_ping(context);
        if (!ping) throw std::runtime_error("EIS input barrier unavailable");
        waiting.emplace(ping,request);
        ei_ping(ping);
    }
    void run() noexcept {
        State terminal=State::Stopped;
        std::string error;
        try {
            context=ei_new_sender(nullptr);
            if (!context) throw std::runtime_error("EIS sender unavailable");
            ei_configure_name(context,"Traverse");
            int duplicate=fcntl(connection.descriptor(),F_DUPFD_CLOEXEC,0);
            if (duplicate < 0) throw std::runtime_error("EIS socket duplication failed");
            int flags=fcntl(duplicate,F_GETFL);
            if (flags < 0 || fcntl(duplicate,F_SETFL,flags|O_NONBLOCK)) { close(duplicate); throw std::runtime_error("EIS socket flags failed"); }
            // The pinned provider's tested contract consumes the descriptor on
            // every setup outcome, including failed epoll registration.
            if (ei_setup_backend_fd(context,duplicate) < 0) throw std::runtime_error("EIS sender setup failed");
            while (!stopping) {
                if (!connection.valid()) { terminal=State::Revoked; break; }
                if (!events()) throw std::runtime_error(termination_reason);
                {
                    std::lock_guard lock(mutex);
                    while (!queued.empty()) {
                        auto request=queued.front(); queued.pop_front();
                        try { send(request); }
                        catch (...) { fail(request,Session::Failure::Transport,"EIS input dispatch failed"); throw; }
                    }
                }
                pollfd fds[]={{ei_get_fd(context),POLLIN,0},{command[0],POLLIN,0},{connection.revocation_descriptor(),POLLIN|POLLHUP,0}};
                int result;
                do { result=poll(fds,3,-1); } while (result < 0 && errno == EINTR);
                if (result < 0) throw std::runtime_error("EIS sender poll failed");
                if (fds[1].revents) drain(command[0]);
            }
        } catch (const std::exception &failure) { terminal=State::Failed; error=failure.what(); }
        if (context) {
            // Normal Stop sends releases only through usable devices. Closing
            // the consumer lease also revokes unusable/paused input authority.
            if (terminal == State::Stopped && connection.valid()) {
                for (auto &[_,device] : devices) if (device.resumed && device.emulating) {
                    clear_holds(device); ei_device_stop_emulating(device.handle);
                }
            }
            for (auto &[ping,_] : waiting) ei_ping_unref(ping);
            for (auto &[handle,_] : devices) ei_device_unref(handle);
            devices.clear();
            for (auto *seat : seats) ei_seat_unref(seat);
            seats.clear();
            ei_unref(context); context=nullptr;
        }
        connection={}; // liveness EOF ends portal authority before final state
        {
            std::lock_guard lock(mutex);
            stopping=true;
            for (auto &request : queued) fail(request,Session::Failure::Cancelled,"EIS input ended");
            queued.clear();
            for (auto &[_,request] : waiting) fail(request,Session::Failure::Cancelled,"EIS delivery unconfirmed");
            waiting.clear();
            value={terminal,error,0,0}; changed.notify();
        }
    }
};
EisInput::EisInput(Session::Connection connection,std::uint32_t granted,Session::Stream stream)
    : impl(std::make_unique<Impl>(std::move(connection),granted,std::move(stream))) {}
EisInput::~EisInput()=default;
EisInput::Snapshot EisInput::snapshot() const { std::lock_guard lock(impl->mutex); return impl->value; }
int EisInput::state_descriptor() const noexcept { return impl->changed.descriptor(); }
std::future<void> EisInput::submit(Session::Input input) { return impl->submit(input,false); }
std::future<void> EisInput::release_held() { return impl->submit({},true); }
void EisInput::stop() { impl->stop(); }
} // namespace traverse
