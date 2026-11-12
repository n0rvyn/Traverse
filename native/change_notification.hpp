#pragma once
#include <cerrno>
#include <fcntl.h>
#include <stdexcept>
#include <unistd.h>

namespace traverse {
// A coalescing wakeup, not a second state store. Both descriptors remain
// reserved until destruction, after the owning component joins its workers.
// Terminal snapshots remain authoritative after the wakeup is drained.
class ChangeNotification {
    int descriptors[2]{-1,-1};
  public:
    ChangeNotification() {
        if (pipe2(descriptors,O_CLOEXEC|O_NONBLOCK))
            throw std::runtime_error("Cannot create native change notification");
    }
    ~ChangeNotification() { close(descriptors[0]); close(descriptors[1]); }
    ChangeNotification(const ChangeNotification &)=delete;
    ChangeNotification &operator=(const ChangeNotification &)=delete;
    int descriptor() const noexcept { return descriptors[0]; }
    void notify() noexcept {
        const char byte=1;
        while (write(descriptors[1],&byte,1)<0 && errno==EINTR) {}
        // EAGAIN means an unread notification already covers this change.
    }
};
}
