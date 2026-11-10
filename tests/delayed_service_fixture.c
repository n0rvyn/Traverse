#define _GNU_SOURCE
/* Owned fault injection only; never installed in the application payload. */
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <time.h>
#include <unistd.h>
int main(int argc,char **argv) {
    const char *owner=NULL,*web=NULL,*parent_text=NULL;
    for(int i=1;i+1<argc;i++) {
        if(!strcmp(argv[i],"--owner-socket"))owner=argv[++i];
        else if(!strcmp(argv[i],"--web"))web=argv[++i];
        else if(!strcmp(argv[i],"--supervisor-pid"))parent_text=argv[++i];
    }
    if(!owner||!web||!parent_text)return 2;
    char *end=NULL;long parent=strtol(parent_text,&end,10);
    if(*end||parent<=1||prctl(PR_SET_PDEATHSIG,SIGTERM)||getppid()!=parent)return 2;
    char waiting[PATH_MAX],gate[PATH_MAX];
    if(snprintf(waiting,sizeof(waiting),"%s.waiting",owner)>=(int)sizeof(waiting)||
       snprintf(gate,sizeof(gate),"%s/.fixture-delay",web)>=(int)sizeof(gate))return 2;
    int fd=open(waiting,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);
    if(fd<0)return 2;
    close(fd);
    while(!access(gate,F_OK)) {
        struct timespec pause={0,50000000};nanosleep(&pause,NULL);
    }
    return 3; /* The fixture is expected to be cancelled while the gate exists. */
}
