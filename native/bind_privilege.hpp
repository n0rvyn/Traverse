#pragma once
#include <linux/capability.h>
#include <stdexcept>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace traverse {
// Call on the binding thread before creating any acceptor or worker threads.
inline void drop_bind_privilege() {
    __user_cap_header_struct header{_LINUX_CAPABILITY_VERSION_3, 0};
    __user_cap_data_struct data[2]{};
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) ||
        syscall(SYS_capset, &header, data) || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        throw std::runtime_error("Cannot drop TLS listener binding privilege");
}
} // namespace traverse
