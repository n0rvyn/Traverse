// Independent actual-X11 receiver and control for an owned synthetic server.
#include "common.hpp"
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/XKBlib.h>
#include <X11/extensions/XTest.h>
#include <poll.h>
int input_worker(const std::string &);
int main(int argc,char **argv) {
    if (argc==3 && std::string(argv[1])=="--worker") return input_worker(argv[2]);
    if (argc!=2) return 2;
    Display *display=XOpenDisplay(argv[1]);if (!display) return 3;
    Window window=XCreateSimpleWindow(display,DefaultRootWindow(display),0,0,640,480,0,0,0);
    XStoreName(display,window,"Traverse host layout receiver");
    XSelectInput(display,window,KeyPressMask|KeyReleaseMask|ExposureMask|StructureNotifyMask);
    XMapWindow(display,window);XSync(display,False);
    XSetInputFocus(display,window,RevertToParent,CurrentTime);
    XAutoRepeatOff(display); // Own test server only, deterministic held-state checks.
    XSync(display,False);
    std::string text;
    auto emit=[](const json &row){std::cout<<row<<std::endl;};
    auto paint=[&] {
        GC gc=DefaultGC(display,DefaultScreen(display));XSetForeground(display,gc,WhitePixel(display,DefaultScreen(display)));
        const std::string label="Traverse host layout receiver";
        XDrawString(display,window,gc,20,35,label.data(),static_cast<int>(label.size()));
        XDrawString(display,window,gc,20,65,text.data(),static_cast<int>(text.size()));XFlush(display);
    };
    auto events=[&] {
        while (XPending(display)) {
            XEvent event;XNextEvent(display,&event);
            if (event.type==MappingNotify) XRefreshKeyboardMapping(&event.xmapping);
            else if (event.type==Expose) paint();
            else if (event.type==KeyPress || event.type==KeyRelease) {
                char buffer[64];KeySym symbol=NoSymbol;
                int length=XLookupString(&event.xkey,buffer,sizeof(buffer),&symbol,nullptr);
                std::string value;
                for (int i=0;i<length;++i) if (buffer[i]>=32 && buffer[i]<127) value+=buffer[i];
                if (event.type==KeyPress) {text+=value;XClearWindow(display,window);paint();}
                emit({{"event","key"},{"code",event.xkey.keycode},{"symbol",symbol},
                    {"down",event.type==KeyPress},{"state",event.xkey.state},{"text",value}});
            }
        }
    };
    auto state=[&](const json &command) {
        XSync(display,False);events();char keys[32];XQueryKeymap(display,keys);
        json held=json::array(),names=json::object();
        for (int code=8;code<256;++code) if (keys[code/8]&(1<<(code%8))) held.push_back(code);
        XkbDescPtr keyboard=XkbGetKeyboard(display,XkbAllComponentsMask,XkbUseCoreKbd);
        if (!keyboard || !keyboard->names || !keyboard->names->keys) throw std::runtime_error("Receiver XKB names unavailable");
        for (int code=keyboard->min_key_code;code<=keyboard->max_key_code;++code) {
            auto raw=keyboard->names->keys[code].name;
            std::string name(raw,strnlen(raw,XkbKeyNameLength));
            if (!name.empty()) names[name]=code;
        }
        XkbFreeKeyboard(keyboard,XkbAllComponentsMask,True);
        emit({{"event","state"},{"id",command.at("id")},{"held",held},{"names",names},{"text",text}});
    };
    emit({{"event","ready"},{"window",window},{"autoRepeat",false}});
    try {
        for (;;) {
            events();pollfd fds[]={{ConnectionNumber(display),POLLIN,0},{STDIN_FILENO,POLLIN|POLLHUP,0}};
            if (poll(fds,2,-1)<0) {if (errno==EINTR) continue;throw std::runtime_error("Receiver poll");}
            events();
            if (fds[1].revents) {
                std::string line;if (!std::getline(std::cin,line)) break;
                auto command=json::parse(line);auto op=command.at("op").get<std::string>();
                if (op=="quit") break;
                if (op=="external") {XTestFakeKeyEvent(display,command.at("code").get<int>(),command.at("down").get<bool>(),CurrentTime);XSync(display,False);}
                else if (op=="focus") {XRaiseWindow(display,window);XSetInputFocus(display,window,RevertToParent,CurrentTime);XSync(display,False);}
                else if (op!="state") throw std::runtime_error("Unknown receiver control");
                state(command);
            }
        }
        XDestroyWindow(display,window);XCloseDisplay(display);return 0;
    } catch (const std::exception &error) {std::cerr<<error.what()<<std::endl;XCloseDisplay(display);return 1;}
}
