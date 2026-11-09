/* Independent X11 screenshot, only for verification. No streaming/encoding. */
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <stdio.h>
#include <stdlib.h>
static unsigned char component(unsigned long pixel,unsigned long mask){
    if(!mask)return 0;
    while(!(mask&1)){mask>>=1;pixel>>=1;}
    return (unsigned char)((pixel&mask)*255/mask);
}
int main(int argc,char **argv){
    if(argc!=2){fprintf(stderr,"usage: %s OUTPUT.ppm\n",argv[0]);return 2;}
    Display *d=XOpenDisplay(NULL);if(!d)return 1;
    int s=DefaultScreen(d),w=DisplayWidth(d,s),h=DisplayHeight(d,s);
    XImage *image=XGetImage(d,RootWindow(d,s),0,0,w,h,AllPlanes,ZPixmap);
    if(!image){XCloseDisplay(d);return 1;}
    FILE *out=fopen(argv[1],"wb");if(!out){XDestroyImage(image);XCloseDisplay(d);return 1;}
    fprintf(out,"P6\n%d %d\n255\n",w,h);
    for(int y=0;y<h;y++)for(int x=0;x<w;x++){
        unsigned long pixel=XGetPixel(image,x,y);
        unsigned char rgb[]={component(pixel,image->red_mask),component(pixel,image->green_mask),component(pixel,image->blue_mask)};
        if(fwrite(rgb,1,3,out)!=3){fclose(out);XDestroyImage(image);XCloseDisplay(d);return 1;}
    }
    int failed=fclose(out);XDestroyImage(image);XCloseDisplay(d);return failed?1:0;
}
