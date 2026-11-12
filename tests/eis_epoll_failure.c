#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <sys/epoll.h>
#include <unistd.h>

/* Linked into the provider probe only. No preloads or host limits. */
static int target_fd = -1;
static int injected;
void eis_probe_arm_failure(int fd) { target_fd = fd; injected = 0; }
int eis_probe_failure_count(void) { return injected; }

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    if (op == EPOLL_CTL_ADD && fd == target_fd) {
        target_fd = -1;
        injected++;
        errno = ENOSPC;
        return -1;
    }
    int (*real_ctl)(int, int, int, struct epoll_event *);
    *(void **)(&real_ctl) = dlsym(RTLD_NEXT, "epoll_ctl");
    if (!real_ctl) _exit(91);
    return real_ctl(epfd, op, fd, event);
}
