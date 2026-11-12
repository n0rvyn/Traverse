#include "common.hpp"
#include <X11/Xlib.h>
#include <X11/XKBlib.h>
#include <X11/extensions/XTest.h>
#include "input_keys.hpp"
#include <cmath>
#include <poll.h>
#include <set>
#include <functional>

class Injector {
    Display *d = nullptr;
    std::map<std::string,KeyCode> keys;
    std::set<unsigned int> buttons;
    std::map<std::string,KeyCode> positions;
    int xkb_event = 0;
    bool names_dirty = true;

    static std::string key_name(const char *bytes) {
        std::string name(bytes,XkbKeyNameLength);
        while (!name.empty() && name.back()=='\0') name.pop_back();
        return name;
    }
    void refresh_positions() {
        while (XPending(d)) {
            XEvent event;
            XNextEvent(d,&event);
            if (event.type==xkb_event) {
                auto *keyboard=reinterpret_cast<XkbEvent *>(&event);
                if (keyboard->any.xkb_type==XkbNewKeyboardNotify ||
                    keyboard->any.xkb_type==XkbMapNotify || keyboard->any.xkb_type==XkbNamesNotify)
                    names_dirty=true;
            } else if (event.type==MappingNotify) names_dirty=true;
        }
        if (!names_dirty) return;
        struct Drop {void operator()(XkbDescPtr value) const {if (value) XkbFreeKeyboard(value,XkbAllComponentsMask,True);}};
        std::unique_ptr<XkbDescRec,Drop> keyboard(XkbGetKeyboard(d,XkbAllComponentsMask,XkbUseCoreKbd));
        if (!keyboard || !keyboard->names || !keyboard->names->keys)
            throw std::runtime_error("Cannot read host keyboard positions");
        std::map<std::string,std::set<KeyCode>> named;
        for (int code=keyboard->min_key_code;code<=keyboard->max_key_code;++code)
            named[key_name(keyboard->names->keys[code].name)].insert(static_cast<KeyCode>(code));
        std::multimap<std::string,std::string> aliases;
        for (int i=0;i<keyboard->names->num_key_aliases;++i) {
            const auto &alias=keyboard->names->key_aliases[i];
            aliases.emplace(key_name(alias.alias),key_name(alias.real));
        }
        std::map<KeyCode,std::vector<std::string>> by_code;
        for (const auto &[dom,position]:traverse::physical_keys()) {
            std::set<KeyCode> candidates;
            std::set<std::string> visited;
            std::function<void(const std::string &)> visit=[&](const std::string &name) {
                if (!visited.insert(name).second) return;
                auto actual=named.find(name);
                if (actual!=named.end()) candidates.insert(actual->second.begin(),actual->second.end());
                auto range=aliases.equal_range(name);
                for (auto alias=range.first;alias!=range.second;++alias) visit(alias->second);
            };
            visit(std::string(position.xkb_name));
            if (candidates.size()==1 && *candidates.begin()!=0) by_code[*candidates.begin()].push_back(dom);
        }
        std::map<std::string,KeyCode> fresh;
        for (const auto &[code,names]:by_code) if (names.size()==1) fresh.emplace(names.front(),code);
        positions.swap(fresh);
        names_dirty=false;
    }

  public:
    explicit Injector(const std::string &name) {
        auto deadline = Clock::now() + std::chrono::seconds(1);
        do {
            d = XOpenDisplay(name.c_str());
            if (d)
                break;
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        } while (Clock::now() < deadline);
        if (!d)
            throw std::runtime_error("Cannot open input display");
        try {
            int a, b, c, e;
            if (!XTestQueryExtension(d, &a, &b, &c, &e))
                throw std::runtime_error("XTest unavailable");
            int opcode,error,major=XkbMajorVersion,minor=XkbMinorVersion;
            if (!XkbQueryExtension(d,&opcode,&xkb_event,&error,&major,&minor))
                throw std::runtime_error("XKB unavailable");
            unsigned mask=XkbNewKeyboardNotifyMask|XkbMapNotifyMask|XkbNamesNotifyMask;
            if (!XkbSelectEvents(d,XkbUseCoreKbd,mask,mask))
                throw std::runtime_error("Host keyboard notifications unavailable");
            refresh_positions();
        } catch (...) {
            XCloseDisplay(d);
            d = nullptr;
            throw;
        }
    }
    ~Injector() {
        if (d) {
            release();
            XCloseDisplay(d);
        }
    }
    void release() {
        for (const auto &[_,key] : keys)
            XTestFakeKeyEvent(d, key, False, CurrentTime);
        for (auto button : buttons)
            XTestFakeButtonEvent(d, button, False, CurrentTime);
        keys.clear();
        buttons.clear();
        XSync(d, False);
    }
    void event(const json &e) {
        auto type = e.at("type").get<std::string>();
        if (type == "release")
            release();
        else if (type == "heartbeat") {
        } else if (type == "move") {
            double x = e.at("x").get<double>(), y = e.at("y").get<double>();
            if (!std::isfinite(x) || !std::isfinite(y) || x < 0 || x > 1 || y < 0 || y > 1)
                throw std::runtime_error("Invalid coordinates");
            Window root;
            int xx, yy;
            unsigned int width, height, border, depth;
            XGetGeometry(d, DefaultRootWindow(d), &root, &xx, &yy, &width, &height, &border,
                         &depth);
            XTestFakeMotionEvent(d, DefaultScreen(d),
                                 static_cast<int>(std::lround(x * (width - 1))),
                                 static_cast<int>(std::lround(y * (height - 1))), CurrentTime);
        } else if (type == "key") {
            auto name = e.at("code").get<std::string>();
            if (!traverse::physical_key(name) || !e.at("down").is_boolean())
                throw std::runtime_error("Unsupported key");
            if (e.at("down").get<bool>()) {
                if (!keys.count(name)) {
                    char state[32];
                    // This existing ownership roundtrip also receives pending
                    // XKB notifications before resolving a new physical press.
                    XQueryKeymap(d, state);
                    refresh_positions();
                    auto position=positions.find(name);
                    if (position==positions.end()) throw std::runtime_error("Key absent from layout");
                    KeyCode code=position->second;
                    if (!(state[code / 8] & (1 << (code % 8)))) {
                        XTestFakeKeyEvent(d, code, True, CurrentTime);
                        keys.emplace(name,code);
                    }
                }
            } else {
                // A release belongs to the admitted press, even if its name
                // vanished or moved in the current keyboard map.
                auto held=keys.find(name);
                if (held!=keys.end()) {
                    XTestFakeKeyEvent(d,held->second,False,CurrentTime);
                    keys.erase(held);
                }
            }
        } else if (type == "button") {
            if (!e.at("button").is_number_integer() || !e.at("down").is_boolean())
                throw std::runtime_error("Invalid button");
            int number = e.at("button").get<int>();
            if (number < 0 || number > 2)
                throw std::runtime_error("Invalid button");
            unsigned int button = number + 1;
            if (e.at("down").get<bool>()) {
                if (!buttons.count(button)) {
                    Window root, child;
                    int a, b, c, f;
                    unsigned int mask;
                    XQueryPointer(d, DefaultRootWindow(d), &root, &child, &a, &b, &c, &f, &mask);
                    if (!(mask & (Button1Mask << (button - 1)))) {
                        XTestFakeButtonEvent(d, button, True, CurrentTime);
                        buttons.insert(button);
                    }
                }
            } else if (buttons.erase(button))
                XTestFakeButtonEvent(d, button, False, CurrentTime);
        } else if (type == "wheel") {
            auto axis = e.at("axis").get<std::string>();
            int direction = e.at("direction").get<int>();
            if ((axis != "x" && axis != "y") || (direction != 1 && direction != -1))
                throw std::runtime_error("Invalid scroll");
            unsigned int button = axis == "y" ? (direction > 0 ? 5 : 4) : (direction > 0 ? 7 : 6);
            XTestFakeButtonEvent(d, button, True, CurrentTime);
            XTestFakeButtonEvent(d, button, False, CurrentTime);
        } else
            throw std::runtime_error("Invalid input type");
        XSync(d, False);
    }
};
int input_worker(const std::string &name) {
    // fd 0 is a full-duplex socket owned by the parent. No other process keeps it.
    std::signal(SIGTERM, signal_stop);
    std::signal(SIGINT, signal_stop);
    Injector injector(name);
    std::string pending;
    char bytes[4096];
    while (!stopping) {
        pollfd p{STDIN_FILENO, POLLIN, 0};
        int ready = poll(&p, 1, 3000);
        if (ready == 0) {
            injector.release();
            continue;
        }
        if (ready < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        ssize_t n = read(STDIN_FILENO, bytes, sizeof(bytes));
        if (n <= 0)
            break;
        pending.append(bytes, static_cast<size_t>(n));
        for (size_t end; (end = pending.find('\n')) != std::string::npos;) {
            auto line = pending.substr(0, end);
            pending.erase(0, end + 1);
            json result;
            try {
                injector.event(json::parse(line));
                result = {{"ok", true}};
            } catch (const std::exception &e) {
                injector.release();
                result = {{"ok", false}, {"error", e.what()}};
            }
            auto response = result.dump() + "\n";
            size_t offset = 0;
            while (offset < response.size()) {
                auto sent = send(STDIN_FILENO, response.data() + offset, response.size() - offset,
                                 MSG_NOSIGNAL);
                if (sent <= 0)
                    return 0;
                offset += sent;
            }
        }
    }
    injector.release();
    return 0;
}
