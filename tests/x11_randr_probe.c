/* Report actual test-display RandR capabilities without changing its mode. */
#include <X11/Xlib.h>
#include <X11/extensions/Xrandr.h>
#include <stdio.h>
int main(void){
    Display *d=XOpenDisplay(NULL);if(!d)return 1;
    Window root=DefaultRootWindow(d);int minw,minh,maxw,maxh;
    if(!XRRGetScreenSizeRange(d,root,&minw,&minh,&maxw,&maxh))return 2;
    XRRScreenResources *r=XRRGetScreenResourcesCurrent(d,root);if(!r)return 3;
    printf("{\"minimum\":[%d,%d],\"maximum\":[%d,%d],\"modes\":[",minw,minh,maxw,maxh);
    for(int i=0;i<r->nmode;i++)printf("%s{\"width\":%u,\"height\":%u}",i?",":"",r->modes[i].width,r->modes[i].height);
    puts("]}");XRRFreeScreenResources(r);XCloseDisplay(d);return 0;
}
