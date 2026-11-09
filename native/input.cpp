#include "common.hpp"
#include <X11/Xlib.h>
#include <X11/extensions/XTest.h>
#include <X11/keysym.h>
#include <cmath>
#include <poll.h>
#include <set>

static std::map<std::string, KeySym> key_symbols() {
    std::map<std::string, KeySym> keys = {{"Space", XK_space},
                                          {"Enter", XK_Return},
                                          {"Tab", XK_Tab},
                                          {"Escape", XK_Escape},
                                          {"Backspace", XK_BackSpace},
                                          {"Delete", XK_Delete},
                                          {"Insert", XK_Insert},
                                          {"Home", XK_Home},
                                          {"End", XK_End},
                                          {"PageUp", XK_Prior},
                                          {"PageDown", XK_Next},
                                          {"ArrowLeft", XK_Left},
                                          {"ArrowRight", XK_Right},
                                          {"ArrowUp", XK_Up},
                                          {"ArrowDown", XK_Down},
                                          {"ShiftLeft", XK_Shift_L},
                                          {"ShiftRight", XK_Shift_R},
                                          {"ControlLeft", XK_Control_L},
                                          {"ControlRight", XK_Control_R},
                                          {"AltLeft", XK_Alt_L},
                                          {"AltRight", XK_Alt_R},
                                          {"MetaLeft", XK_Super_L},
                                          {"MetaRight", XK_Super_R},
                                          {"Minus", XK_minus},
                                          {"Equal", XK_equal},
                                          {"BracketLeft", XK_bracketleft},
                                          {"BracketRight", XK_bracketright},
                                          {"Backslash", XK_backslash},
                                          {"Semicolon", XK_semicolon},
                                          {"Quote", XK_apostrophe},
                                          {"Backquote", XK_grave},
                                          {"Comma", XK_comma},
                                          {"Period", XK_period},
                                          {"Slash", XK_slash}};
    for (char c = 'A'; c <= 'Z'; c++)
        keys[std::string("Key") + c] = XK_a + (c - 'A');
    for (char c = '0'; c <= '9'; c++)
        keys[std::string("Digit") + c] = XK_0 + (c - '0');
    for (int n = 1; n <= 12; n++)
        keys["F" + std::to_string(n)] = XK_F1 + n - 1;
    return keys;
}
class Injector {
    Display *d = nullptr;
    std::set<KeyCode> keys;
    std::set<unsigned int> buttons;

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
        int a, b, c, e;
        if (!XTestQueryExtension(d, &a, &b, &c, &e)) {
            XCloseDisplay(d);
            d = nullptr;
            throw std::runtime_error("XTest unavailable");
        }
    }
    ~Injector() {
        if (d) {
            release();
            XCloseDisplay(d);
        }
    }
    void release() {
        for (auto key : keys)
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
            static const auto symbols = key_symbols();
            auto name = e.at("code").get<std::string>();
            if (!symbols.count(name) || !e.at("down").is_boolean())
                throw std::runtime_error("Unsupported key");
            KeyCode code = XKeysymToKeycode(d, symbols.at(name));
            if (!code)
                throw std::runtime_error("Key absent from layout");
            if (e.at("down").get<bool>()) {
                if (!keys.count(code)) {
                    char state[32];
                    XQueryKeymap(d, state);
                    if (!(state[code / 8] & (1 << (code % 8)))) {
                        XTestFakeKeyEvent(d, code, True, CurrentTime);
                        keys.insert(code);
                    }
                }
            } else if (keys.erase(code))
                XTestFakeKeyEvent(d, code, False, CurrentTime);
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
