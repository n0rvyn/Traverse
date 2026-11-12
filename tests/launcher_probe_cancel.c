/* Test-only interposer: deliver SIGTERM at the owned launcher HTTPS probe. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
int connect(int fd,const struct sockaddr *address,socklen_t size) {
    static int (*original)(int,const struct sockaddr *,socklen_t);
    if (!original) original=dlsym(RTLD_NEXT,"connect");
    char executable[4096];ssize_t n=readlink("/proc/self/exe",executable,sizeof(executable)-1);
    const char *port=getenv("TRAVERSE_TEST_CANCEL_PORT");
    if(n>0) executable[n]=0;
    const char *name=n>0?strrchr(executable,'/'):NULL;
    if(name && !strcmp(name+1,"traverse-launcher") && port && address->sa_family==AF_INET &&
       ntohs(((const struct sockaddr_in *)address)->sin_port)==atoi(port)) {
        const char *marker=getenv("TRAVERSE_TEST_CANCEL_MARKER");
        int out=marker?open(marker,O_CREAT|O_WRONLY|O_EXCL|O_CLOEXEC,0600):-1;
        if(out>=0){write(out,"signal-before-probe",19);close(out);}
        raise(SIGTERM);errno=EINTR;return -1;
    }
    return original(fd,address,size);
}
