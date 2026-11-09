/* Real X11 test window: input state is recorded independently of the streamer.
 * gcc tests/desktop_fixture.c -o .runtime/desktop-fixture -lX11
 * DISPLAY=:99 .runtime/desktop-fixture /tmp/traverse-fixture.json
 */
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/keysym.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static Display *display;
static Window window;
static GC gc;
static int width=1024, height=720, px=0, py=0, scroll_y=0, scroll_x=0;
static unsigned int modifiers=0;
static unsigned long presses=0, releases=0, clicks=0, revision=0, visual_id=0;
static char *text;
static size_t text_length=0, text_capacity=0;
static char last_key[128]="none";
static void append_text(unsigned char value) {
    if(text_length>SIZE_MAX-2){fputs("fixture text size overflow\n",stderr);exit(1);}
    if(text_length+2>text_capacity){
        size_t capacity=text_capacity?text_capacity:1024;
        while(capacity<text_length+2)capacity=capacity>SIZE_MAX/2?text_length+2:capacity*2;
        char *grown=realloc(text,capacity);
        if(!grown){perror("fixture text allocation");exit(1);}
        text=grown;text_capacity=capacity;
    }
    text[text_length++]=(char)value;text[text_length]=0;
}
static const char *state_path;

static void save(void) {
    /* All text comes from a restricted ASCII input set; escape JSON explicitly. */
    char tmp[4096];
    snprintf(tmp,sizeof(tmp),"%s.tmp.%ld",state_path,(long)getpid());
    FILE *f=fopen(tmp,"w");
    if(!f){perror("fixture state");exit(1);}
    fprintf(f,"{\"revision\":%lu,\"pointer\":[%d,%d],\"scrollY\":%d,\"scrollX\":%d,\"presses\":%lu,\"releases\":%lu,\"clicks\":%lu,\"modifiers\":%u,\"lastKey\":\"%s\",\"size\":[%d,%d],\"text\":\"",revision,px,py,scroll_y,scroll_x,presses,releases,clicks,modifiers,last_key,width,height);
    for(size_t i=0;i<text_length;i++) {
        unsigned char c=(unsigned char)text[i];
        if(c=='"'||c=='\\')fputc('\\',f);
        if(c>=32&&c<127)fputc(c,f);
    }
    fputs("\"}\n",f);
    if(fclose(f)||rename(tmp,state_path)){perror("fixture state commit");exit(1);}
}
static void line(int x,int y,const char *s,unsigned long color) {
    XSetForeground(display,gc,color);
    XDrawString(display,window,gc,x,y,s,(int)strlen(s));
}
static void draw(void) {
    XSetForeground(display,gc,0x152030);
    XFillRectangle(display,window,gc,0,0,width,height);
    /* Machine-readable visual marker. Revision is also visible as text below. */
    XSetForeground(display,gc,0x200000|((visual_id&255)<<8)|((visual_id*37)&255));
    XFillRectangle(display,window,gc,0,0,64,64);
    line(90,40,"TRAVERSE / REAL X11 DESKTOP",0x91e4ca);
    line(32,100,"Readability: ABCDEFGHIJKLMNOPQRSTUVWXYZ 0123456789",0xffffff);
    line(32,125,"Small text: il1I O0 [] {} () ; : , . / \\ @ # $ % & *",0xc4cfdf);
    char info[1400];
    snprintf(info,sizeof(info),"Typing: %s",text);
    line(32,180,info,0xffffff);
    snprintf(info,sizeof(info),"Last key: %s    presses: %lu    releases: %lu    modifiers: %u",last_key,presses,releases,modifiers);
    line(32,220,info,0xc4cfdf);
    snprintf(info,sizeof(info),"Pointer: %d, %d    clicks: %lu    scroll: %d / %d",px,py,clicks,scroll_x,scroll_y);
    line(32,260,info,0xc4cfdf);
    snprintf(info,sizeof(info),"Revision: %lu    window: %d x %d",revision,width,height);
    line(32,300,info,0xc4cfdf);
    for(int row=0;row<8;row++) {
        snprintf(info,sizeof(info),"%02d  Linux desktop scrolling and image clarity fixture",row+scroll_y);
        line(32,350+row*35,info,row%2?0x8d9eb7:0xd6dfeb);
    }
    XSetForeground(display,gc,0x91e4ca);
    XDrawRectangle(display,window,gc,2,2,width-5,height-5);
    XFlush(display);
}
int main(int argc,char **argv) {
    if(argc!=2){fprintf(stderr,"usage: %s STATE_JSON\n",argv[0]);return 2;}
    state_path=argv[1];
    text=calloc(1,1024);
    if(!text){perror("fixture text allocation");return 1;}
    text_capacity=1024;
    display=XOpenDisplay(NULL);
    if(!display){fprintf(stderr,"XOpenDisplay failed\n");return 1;}
    int screen=DefaultScreen(display);
    width=DisplayWidth(display,screen);height=DisplayHeight(display,screen);
    window=XCreateSimpleWindow(display,RootWindow(display,screen),0,0,width,height,0,0,0x152030);
    XStoreName(display,window,"Traverse input and readability fixture");
    XSelectInput(display,window,ExposureMask|KeyPressMask|KeyReleaseMask|ButtonPressMask|ButtonReleaseMask|PointerMotionMask|StructureNotifyMask);
    gc=XCreateGC(display,window,0,NULL);
    XFontStruct *font=XLoadQueryFont(display,"9x15");
    if(font)XSetFont(display,gc,font->fid);
    XMapWindow(display,window);
    /* A window manager redirects mapping; focus requires a viewable window. */
    XEvent mapped;
    do {XWindowEvent(display,window,StructureNotifyMask,&mapped);} while(mapped.type!=MapNotify);
    XSetInputFocus(display,window,RevertToParent,CurrentTime);
    XSync(display,False);
    printf("window=%lu pid=%ld\n",window,(long)getpid());fflush(stdout);
    save();
    for(;;){
        XEvent e;XNextEvent(display,&e);
        int changed=1;
        switch(e.type){
        case Expose:draw();changed=0;break;
        case ConfigureNotify:width=e.xconfigure.width;height=e.xconfigure.height;break;
        case MotionNotify:px=e.xmotion.x;py=e.xmotion.y;break;
        case ButtonPress:
            px=e.xbutton.x;py=e.xbutton.y;modifiers=e.xbutton.state;
            if(e.xbutton.button==4)scroll_y--;
            else if(e.xbutton.button==5)scroll_y++;
            else if(e.xbutton.button==6)scroll_x--;
            else if(e.xbutton.button==7)scroll_x++;
            else clicks++;
            XSetInputFocus(display,window,RevertToParent,CurrentTime);break;
        case ButtonRelease:break;
        case KeyPress:{
            presses++;modifiers=e.xkey.state;
            char buf[32];KeySym symbol;
            int n=XLookupString(&e.xkey,buf,sizeof(buf),&symbol,NULL);
            if(symbol==XK_F8)visual_id++;
            const char *name=XKeysymToString(symbol);
            snprintf(last_key,sizeof(last_key),"%s",name?name:"unknown");
            if(symbol==XK_BackSpace){if(text_length)text[--text_length]=0;}
            else if(n>0 && !(modifiers&(ControlMask|Mod1Mask|Mod4Mask))) {
                for(int i=0;i<n;i++)if(buf[i]>=32 && buf[i]<127)append_text((unsigned char)buf[i]);
            }
            break;
        }
        case KeyRelease:releases++;modifiers=e.xkey.state;break;
        default:changed=0;
        }
        if(changed){revision++;save();draw();}
    }
}
