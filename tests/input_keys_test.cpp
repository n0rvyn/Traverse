#include "input_keys.hpp"
#include <X11/keysym.h>
#include <X11/Xlib.h>
#include <iostream>
#include <set>

// Characterization of the exact pre-extraction table, using X11 header values.
static std::map<std::string, KeySym> original_x11_symbols() {
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
int main() {
    auto actual = traverse::key_symbols();
    auto original = original_x11_symbols();
    if (actual.size() != original.size()) return 1;
    for (const auto &[code, symbol] : original) {
        if (!actual.count(code) || actual.at(code) != symbol) {
            std::cerr << "Changed X11 key mapping: " << code << '\n';
            return 1;
        }
    }
    const auto &positions=traverse::physical_keys();
    if (positions.size()!=original.size()) return 2;
    std::set<std::int32_t> raw_codes;
    std::set<std::string_view> names;
    for (const auto &[code,position] : positions) {
        if (!original.count(code) || !traverse::valid_keyboard_keycode(position.evdev_code) ||
            position.xkb_name.empty() || position.xkb_name.size()>4 ||
            !raw_codes.insert(position.evdev_code).second || !names.insert(position.xkb_name).second) return 3;
    }
    auto a=traverse::physical_key("KeyA"),q=traverse::physical_key("KeyQ");
    if (!a || !q || a->evdev_code!=30 || q->evdev_code!=16 || a->xkb_name!="AC01" || q->xkb_name!="AD01") return 4;
    if (traverse::physical_key("a") || traverse::physical_key("Unidentified")) return 5;
    std::cout << actual.size() << " original key mappings preserved\n";
}
