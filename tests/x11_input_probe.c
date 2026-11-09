/* Independent local X11/XTest probe for the authorized disposable test display.
 * Never exposed on the network. Used to inspect key/button state after failures.
 */
#include <X11/Xlib.h>
#include <X11/keysym.h>
#include <X11/Xatom.h>
#include <X11/extensions/XTest.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int held(Display *d,const char *name,char state[32]){
    KeyCode code=XKeysymToKeycode(d,XStringToKeysym(name));
    return code && (state[code/8]&(1<<(code%8)))?1:0;
}
static Window find_window(Display *d,Window parent,const char *title){
    char *name=NULL;
    if(XFetchName(d,parent,&name) && name){
        int match=!strcmp(name,title);XFree(name);
        if(match)return parent;
    }
    Window root,up,*children=NULL;unsigned int count=0;
    if(!XQueryTree(d,parent,&root,&up,&children,&count))return None;
    Window result=None;
    for(unsigned int i=0;i<count && !result;i++)result=find_window(d,children[i],title);
    if(children)XFree(children);
    return result;
}
int main(int argc,char **argv){
    Display *d=XOpenDisplay(NULL);if(!d){fputs("XOpenDisplay failed\n",stderr);return 1;}
    if(argc==3 && (!strcmp(argv[1],"window") || !strcmp(argv[1],"focus"))){
        Window w=find_window(d,DefaultRootWindow(d),argv[2]);
        if(!w){fputs("Named window not found\n",stderr);XCloseDisplay(d);return 3;}
        if(!strcmp(argv[1],"focus")){
            XEvent event={0};event.xclient.type=ClientMessage;event.xclient.window=w;
            event.xclient.message_type=XInternAtom(d,"_NET_ACTIVE_WINDOW",False);
            event.xclient.format=32;event.xclient.data.l[0]=2;
            XSendEvent(d,DefaultRootWindow(d),False,SubstructureRedirectMask|SubstructureNotifyMask,&event);
            XRaiseWindow(d,w);XSetInputFocus(d,w,RevertToParent,CurrentTime);XSync(d,False);
        }
        XWindowAttributes a;XGetWindowAttributes(d,w,&a);int x,y;Window child;
        XTranslateCoordinates(d,w,DefaultRootWindow(d),0,0,&x,&y,&child);
        printf("{\"id\":%lu,\"x\":%d,\"y\":%d,\"width\":%d,\"height\":%d,\"mapped\":%d}\n",w,x,y,a.width,a.height,a.map_state==IsViewable);
        XCloseDisplay(d);return 0;
    }else if(argc==2 && !strcmp(argv[1],"click")){
        XTestFakeButtonEvent(d,1,True,CurrentTime);
        XTestFakeButtonEvent(d,1,False,CurrentTime);XSync(d,False);
    }else if(argc==3 && !strcmp(argv[1],"press")){
        KeyCode code=XKeysymToKeycode(d,XStringToKeysym(argv[2]));
        if(!code){XCloseDisplay(d);return 2;}
        XTestFakeKeyEvent(d,code,True,CurrentTime);
        XTestFakeKeyEvent(d,code,False,CurrentTime);XSync(d,False);
    }else if(argc==4 && !strcmp(argv[1],"key")){
        KeyCode code=XKeysymToKeycode(d,XStringToKeysym(argv[2]));
        if(!code || (strcmp(argv[3],"down")&&strcmp(argv[3],"up"))){XCloseDisplay(d);return 2;}
        XTestFakeKeyEvent(d,code,!strcmp(argv[3],"down"),CurrentTime);XSync(d,False);
    }else if(argc==4 && !strcmp(argv[1],"move")){
        XTestFakeMotionEvent(d,DefaultScreen(d),atoi(argv[2]),atoi(argv[3]),CurrentTime);XSync(d,False);
    }else if(argc!=2 || strcmp(argv[1],"query")){
        fputs("usage: x11-input-probe query | key KEYSYM down|up | press KEYSYM | move X Y | window TITLE | focus TITLE\n",stderr);XCloseDisplay(d);return 2;
    }
    char state[32];XQueryKeymap(d,state);
    Window root,child;int rx,ry,wx,wy;unsigned int mask;
    XQueryPointer(d,DefaultRootWindow(d),&root,&child,&rx,&ry,&wx,&wy,&mask);
    printf("{\"shift\":%d,\"control\":%d,\"alt\":%d,\"super\":%d,\"button1\":%d,\"button2\":%d,\"button3\":%d,\"pointer\":[%d,%d]}\n",
      held(d,"Shift_L",state)||held(d,"Shift_R",state),held(d,"Control_L",state)||held(d,"Control_R",state),
      held(d,"Alt_L",state)||held(d,"Alt_R",state),held(d,"Super_L",state)||held(d,"Super_R",state),
      !!(mask&Button1Mask),!!(mask&Button2Mask),!!(mask&Button3Mask),rx,ry);
    XCloseDisplay(d);return 0;
}
