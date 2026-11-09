#define _GNU_SOURCE
/* Only system libc is linked here. File capabilities must never enter a loader
 * that depends on user-controlled LD_LIBRARY_PATH or a private C++ runtime. */
#include <errno.h>
#include <ftw.h>
#include <limits.h>
#include <linux/capability.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static void fail(const char *message) {
    fprintf(stderr, "Traverse binding helper: %s\n", message);
    exit(1);
}
static void join(char *result, const char *prefix, const char *suffix) {
    if (snprintf(result, PATH_MAX, "%s%s", prefix, suffix) >= PATH_MAX)
        fail("Installed path is too long");
}
static void trusted(const char *path, int directory) {
    struct stat st;
    if (lstat(path, &st) || st.st_uid != 0 || (st.st_mode & 0022) ||
        (directory ? !S_ISDIR(st.st_mode) : !S_ISREG(st.st_mode)))
        fail("Installation must be root-owned and not writable by other users");
}
static int visit(const char *path, const struct stat *st, int type, struct FTW *where) {
    (void)where;
    if (!st || (type != FTW_F && type != FTW_D)) {
        fprintf(stderr, "Traverse binding helper: Cannot inspect runtime entry: %s (type %d)\n", path, type);
        exit(1);
    }
    if (st->st_uid != 0 || (st->st_mode & 0022) ||
        (!S_ISREG(st->st_mode) && !S_ISDIR(st->st_mode))) {
        fprintf(stderr, "Traverse binding helper: Untrusted runtime entry: %s (uid %lu, mode %04o)\n",
                path, (unsigned long)st->st_uid, (unsigned)(st->st_mode & 07777));
        exit(1);
    }
    return 0;
}
static void value(const char *name, const char *text) {
    if (setenv(name, text, 1))
        fail("Cannot prepare private runtime environment");
}
static void private_path(const char *name, const char *prefix, const char *suffix) {
    char path[PATH_MAX];
    join(path, prefix, suffix);
    value(name, path);
}
int main(int argc, char **argv) {
    if (argc < 2 || (strcmp(argv[1], "service") && strcmp(argv[1], "frontend")))
        fail("Expected the fixed service or frontend role");
    if (!getuid() || getuid() != geteuid() || getgid() != getegid())
        fail("Run Traverse as the desktop owner, without a UID or GID change");
    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct data[2] = {{0}};
    const unsigned binding = 1U << CAP_NET_BIND_SERVICE;
    if (syscall(SYS_capget, &header, data) || data[0].effective != binding ||
        data[0].permitted != binding || (data[0].inheritable & ~binding) ||
        data[1].effective || data[1].permitted || data[1].inheritable)
        fail("Only CAP_NET_BIND_SERVICE is required; install the native package binding permission");
    pid_t parent = getppid();
    int guarded = 0;
    for (int i = 2; i < argc; ++i) {
        if (!strcmp(argv[i], "--supervisor-pid")) {
            char *end = NULL;
            if (guarded || ++i == argc || !argv[i][0])
                fail("Invalid supervisor PID");
            errno = 0;
            long number = strtol(argv[i], &end, 10);
            if (errno || *end || number <= 1 || number != parent)
                fail("Supervisor unavailable");
            guarded = 1;
        }
    }
    if (!guarded || prctl(PR_SET_PDEATHSIG, SIGTERM) || getppid() != parent)
        fail("Supervisor unavailable");

    char prefix[PATH_MAX], target[PATH_MAX];
    ssize_t count = readlink("/proc/self/exe", prefix, sizeof(prefix) - 1);
    if (count < 0 || count == (ssize_t)sizeof(prefix) - 1)
        fail("Cannot locate installed helper");
    prefix[count] = 0;
    const char *ending = "/libexec/traverse/traverse-bind-helper";
    size_t length = strlen(prefix), tail = strlen(ending);
    if (length <= tail || strcmp(prefix + length - tail, ending))
        fail("Unexpected helper installation path");
    prefix[length - tail] = 0;
    /* Validate every ancestor and the complete dependency/plugin/registry tree.
     * Once all ancestors are trusted, an unprivileged caller cannot swap them. */
    trusted("/", 1);
    for (char *part = prefix + 1; *part; ++part) {
        if (*part == '/') {
            *part = 0;
            trusted(prefix, 1);
            *part = '/';
        }
    }
    trusted(prefix, 1);
    if (nftw(prefix, visit, 32, FTW_PHYS))
        fail("Cannot validate installed runtime");
    join(target, prefix, !strcmp(argv[1], "service")
                             ? "/libexec/traverse/traverse-service"
                             : "/libexec/traverse/traverse-tls-frontend");
    trusted(target, 0);
    char registry[PATH_MAX];
    join(registry, prefix, "/share/traverse/registry.bin");
    trusted(registry, 0);
    if (access(target, X_OK))
        fail("Installed role is not executable");

    if (clearenv())
        fail("Cannot clear inherited environment");
    // These network-only roles receive absolute paths. Desktop/session access
    // stays in the unprivileged adapter, not this capability-bearing process.
    if (chdir(prefix))
        fail("Cannot enter trusted private runtime directory");
    value("HOME", prefix);
    value("PATH", "/usr/bin:/bin");
    value("LANG", "C.UTF-8");
    value("TRAVERSE_RUNTIME_PREFIX", prefix);
    private_path("LD_LIBRARY_PATH", prefix, "/lib");
    private_path("GST_PLUGIN_SYSTEM_PATH", prefix, "/lib/gstreamer-1.0");
    private_path("GST_PLUGIN_SYSTEM_PATH_1_0", prefix, "/lib/gstreamer-1.0");
    value("GST_PLUGIN_PATH", "");
    value("GST_PLUGIN_PATH_1_0", "");
    private_path("GST_PLUGIN_SCANNER", prefix, "/libexec/gstreamer-1.0/gst-plugin-scanner");
    private_path("GST_PLUGIN_SCANNER_1_0", prefix, "/libexec/gstreamer-1.0/gst-plugin-scanner");
    value("GST_REGISTRY", registry);
    value("GST_REGISTRY_1_0", registry);
    value("GST_REGISTRY_UPDATE", "no");
    /* No inherited OpenSSL/provider/loader/plugin configuration is accepted.
     * OpenSSL's compiled default config/provider search remains unchanged. */
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0))
        fail("Cannot clear inherited ambient capabilities");
    data[0].effective = data[0].permitted = data[0].inheritable = binding;
    if (syscall(SYS_capset, &header, data) ||
        prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_NET_BIND_SERVICE, 0, 0) ||
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        fail("Cannot retain only the binding capability");
    argv[1] = target;
    execv(target, argv + 1);
    fail("Cannot execute the installed role");
}
