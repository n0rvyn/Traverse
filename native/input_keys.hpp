#pragma once
#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <cmath>
#include <linux/input-event-codes.h>

namespace traverse {
inline bool valid_pointer_position(double x, double y, std::int32_t width, std::int32_t height) {
    return std::isfinite(x) && std::isfinite(y) && x >= 0 && y >= 0 && x < width && y < height;
}
inline bool valid_pointer_button(std::int32_t code) { return code >= BTN_LEFT && code <= BTN_MIDDLE; }
inline bool valid_discrete_axis(std::int32_t axis, std::int32_t steps) {
    return (axis == 0 || axis == 1) && (steps == 1 || steps == -1);
}
inline bool valid_keyboard_keycode(std::int32_t code) {
    return code >= KEY_ESC && code <= KEY_MAX &&
        !(code >= BTN_MISC && code < KEY_OK) &&
        !(code >= BTN_DPAD_UP && code <= BTN_DPAD_RIGHT) &&
        !(code >= BTN_TRIGGER_HAPPY && code <= BTN_TRIGGER_HAPPY40);
}
struct PhysicalKey {
    std::int32_t evdev_code;
    std::string_view xkb_name;
};
// KeyboardEvent.code names physical positions, independently of the host's
// symbols. X11 must resolve xkb_name from its actual map, not assume evdev+8.
inline const std::map<std::string, PhysicalKey> &physical_keys() {
    static const std::map<std::string, PhysicalKey> keys = {
        {"Space",{KEY_SPACE,"SPCE"}}, {"Enter",{KEY_ENTER,"RTRN"}},
        {"Tab",{KEY_TAB,"TAB"}}, {"Escape",{KEY_ESC,"ESC"}},
        {"Backspace",{KEY_BACKSPACE,"BKSP"}}, {"Delete",{KEY_DELETE,"DELE"}},
        {"Insert",{KEY_INSERT,"INS"}}, {"Home",{KEY_HOME,"HOME"}},
        {"End",{KEY_END,"END"}}, {"PageUp",{KEY_PAGEUP,"PGUP"}},
        {"PageDown",{KEY_PAGEDOWN,"PGDN"}}, {"ArrowLeft",{KEY_LEFT,"LEFT"}},
        {"ArrowRight",{KEY_RIGHT,"RGHT"}}, {"ArrowUp",{KEY_UP,"UP"}},
        {"ArrowDown",{KEY_DOWN,"DOWN"}},
        {"ShiftLeft",{KEY_LEFTSHIFT,"LFSH"}}, {"ShiftRight",{KEY_RIGHTSHIFT,"RTSH"}},
        {"ControlLeft",{KEY_LEFTCTRL,"LCTL"}}, {"ControlRight",{KEY_RIGHTCTRL,"RCTL"}},
        {"AltLeft",{KEY_LEFTALT,"LALT"}}, {"AltRight",{KEY_RIGHTALT,"RALT"}},
        {"MetaLeft",{KEY_LEFTMETA,"LWIN"}}, {"MetaRight",{KEY_RIGHTMETA,"RWIN"}},
        {"Minus",{KEY_MINUS,"AE11"}}, {"Equal",{KEY_EQUAL,"AE12"}},
        {"BracketLeft",{KEY_LEFTBRACE,"AD11"}}, {"BracketRight",{KEY_RIGHTBRACE,"AD12"}},
        {"Backslash",{KEY_BACKSLASH,"BKSL"}}, {"Semicolon",{KEY_SEMICOLON,"AC10"}},
        {"Quote",{KEY_APOSTROPHE,"AC11"}}, {"Backquote",{KEY_GRAVE,"TLDE"}},
        {"Comma",{KEY_COMMA,"AB08"}}, {"Period",{KEY_DOT,"AB09"}}, {"Slash",{KEY_SLASH,"AB10"}},
        {"KeyA",{KEY_A,"AC01"}}, {"KeyB",{KEY_B,"AB05"}}, {"KeyC",{KEY_C,"AB03"}},
        {"KeyD",{KEY_D,"AC03"}}, {"KeyE",{KEY_E,"AD03"}}, {"KeyF",{KEY_F,"AC04"}},
        {"KeyG",{KEY_G,"AC05"}}, {"KeyH",{KEY_H,"AC06"}}, {"KeyI",{KEY_I,"AD08"}},
        {"KeyJ",{KEY_J,"AC07"}}, {"KeyK",{KEY_K,"AC08"}}, {"KeyL",{KEY_L,"AC09"}},
        {"KeyM",{KEY_M,"AB07"}}, {"KeyN",{KEY_N,"AB06"}}, {"KeyO",{KEY_O,"AD09"}},
        {"KeyP",{KEY_P,"AD10"}}, {"KeyQ",{KEY_Q,"AD01"}}, {"KeyR",{KEY_R,"AD04"}},
        {"KeyS",{KEY_S,"AC02"}}, {"KeyT",{KEY_T,"AD05"}}, {"KeyU",{KEY_U,"AD07"}},
        {"KeyV",{KEY_V,"AB04"}}, {"KeyW",{KEY_W,"AD02"}}, {"KeyX",{KEY_X,"AB02"}},
        {"KeyY",{KEY_Y,"AD06"}}, {"KeyZ",{KEY_Z,"AB01"}},
        {"Digit1",{KEY_1,"AE01"}}, {"Digit2",{KEY_2,"AE02"}}, {"Digit3",{KEY_3,"AE03"}},
        {"Digit4",{KEY_4,"AE04"}}, {"Digit5",{KEY_5,"AE05"}}, {"Digit6",{KEY_6,"AE06"}},
        {"Digit7",{KEY_7,"AE07"}}, {"Digit8",{KEY_8,"AE08"}}, {"Digit9",{KEY_9,"AE09"}},
        {"Digit0",{KEY_0,"AE10"}},
        {"F1",{KEY_F1,"FK01"}}, {"F2",{KEY_F2,"FK02"}}, {"F3",{KEY_F3,"FK03"}},
        {"F4",{KEY_F4,"FK04"}}, {"F5",{KEY_F5,"FK05"}}, {"F6",{KEY_F6,"FK06"}},
        {"F7",{KEY_F7,"FK07"}}, {"F8",{KEY_F8,"FK08"}}, {"F9",{KEY_F9,"FK09"}},
        {"F10",{KEY_F10,"FK10"}}, {"F11",{KEY_F11,"FK11"}}, {"F12",{KEY_F12,"FK12"}}
    };
    return keys;
}
inline const PhysicalKey *physical_key(const std::string &code) {
    const auto &keys=physical_keys();
    const auto found=keys.find(code);
    return found==keys.end() ? nullptr : &found->second;
}
inline std::map<std::string, std::uint32_t> key_symbols() {
    std::map<std::string, std::uint32_t> keys = {{"Space", 0x20},
                                          {"Enter", 0xff0d},
                                          {"Tab", 0xff09},
                                          {"Escape", 0xff1b},
                                          {"Backspace", 0xff08},
                                          {"Delete", 0xffff},
                                          {"Insert", 0xff63},
                                          {"Home", 0xff50},
                                          {"End", 0xff57},
                                          {"PageUp", 0xff55},
                                          {"PageDown", 0xff56},
                                          {"ArrowLeft", 0xff51},
                                          {"ArrowRight", 0xff53},
                                          {"ArrowUp", 0xff52},
                                          {"ArrowDown", 0xff54},
                                          {"ShiftLeft", 0xffe1},
                                          {"ShiftRight", 0xffe2},
                                          {"ControlLeft", 0xffe3},
                                          {"ControlRight", 0xffe4},
                                          {"AltLeft", 0xffe9},
                                          {"AltRight", 0xffea},
                                          {"MetaLeft", 0xffeb},
                                          {"MetaRight", 0xffec},
                                          {"Minus", 0x2d},
                                          {"Equal", 0x3d},
                                          {"BracketLeft", 0x5b},
                                          {"BracketRight", 0x5d},
                                          {"Backslash", 0x5c},
                                          {"Semicolon", 0x3b},
                                          {"Quote", 0x27},
                                          {"Backquote", 0x60},
                                          {"Comma", 0x2c},
                                          {"Period", 0x2e},
                                          {"Slash", 0x2f}};
    for (char c = 'A'; c <= 'Z'; c++)
        keys[std::string("Key") + c] = 0x61 + (c - 'A');
    for (char c = '0'; c <= '9'; c++)
        keys[std::string("Digit") + c] = 0x30 + (c - '0');
    for (int n = 1; n <= 12; n++)
        keys["F" + std::to_string(n)] = 0xffbe + n - 1;
    return keys;
}
} // namespace traverse
