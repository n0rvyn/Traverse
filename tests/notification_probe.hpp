#pragma once
#include <chrono>
#include <future>
#include <poll.h>
#include <stdexcept>
#include <unistd.h>
#include <cerrno>
#include <fcntl.h>

inline void drain_notification(int fd) {
    int descriptor_flags=fcntl(fd,F_GETFD),status_flags=fcntl(fd,F_GETFL);
    if (descriptor_flags<0 || status_flags<0 || !(descriptor_flags&FD_CLOEXEC) || !(status_flags&O_NONBLOCK))
        throw std::runtime_error("Notification must remain reserved, nonblocking and close-on-exec");
    char bytes[256];
    for (;;) {
        auto count=read(fd,bytes,sizeof(bytes));
        if (count>0 || (count<0 && errno==EINTR)) continue;
        if (count<0 && (errno==EAGAIN || errno==EWOULDBLOCK)) return;
        throw std::runtime_error("Notification descriptor unexpectedly closed");
    }
}
template<class Ready> void notification_until(int fd, Ready ready) {
    // Explicit test watchdog. Always require a wakeup, including a result that
    // completed synchronously; never turn repeated readiness checks into a poll.
    auto end=std::chrono::steady_clock::now()+std::chrono::seconds(5);
    do {
        auto left=std::chrono::duration_cast<std::chrono::milliseconds>(end-std::chrono::steady_clock::now()).count();
        if (left<=0) throw std::runtime_error("No native completion notification");
        pollfd item{fd,POLLIN,0};
        int result=poll(&item,1,static_cast<int>(left));
        if (result<0 && errno==EINTR) continue;
        if (result<=0 || !(item.revents&POLLIN)) throw std::runtime_error("No native completion notification");
        drain_notification(fd);
        if (ready()) return;
    } while (true);
}
template<class T> void notified_future(int fd,std::future<T> &future) {
    notification_until(fd,[&] { return future.wait_for(std::chrono::seconds(0))==std::future_status::ready; });
}
