#include "wayland_guardian.hpp"
// Private worker entry, shared by installed and diagnostic executables.
#include <gst/gst.h>
#include <cstdlib>
#include <cerrno>
#include <limits>
#include <fcntl.h>
#include <unistd.h>
int main(int argc,char **argv) {
    if (argc!=2) return 2;
    char *end=nullptr;
    errno=0;
    auto parent=strtol(argv[1],&end,10);
    if (errno || !end || *end || parent<=1 || parent>std::numeric_limits<pid_t>::max()) return 2;
    int flags=fcntl(STDIN_FILENO,F_GETFD);
    if (flags<0 || fcntl(STDIN_FILENO,F_SETFD,flags|FD_CLOEXEC)) return 1;
    gst_init(nullptr,nullptr);
    int result=traverse::wayland_guardian_worker(STDIN_FILENO,static_cast<pid_t>(parent));
    gst_deinit();
    return result;
}
