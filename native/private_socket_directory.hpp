#pragma once
#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include <fcntl.h>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <vector>

namespace traverse {
// Socket paths have a much smaller limit than ordinary configuration paths.
// Keep them directly below the private runtime base, independently of the
// longer instance identifier used for files and owner-channel authentication.
class PrivateSocketDirectory {
    int parent = -1;
    std::string name;
    struct stat identity{};

    void cleanup() noexcept {
        if (parent < 0)
            return;
        struct stat current{};
        if (!name.empty() && !fstatat(parent, name.c_str(), &current, AT_SYMLINK_NOFOLLOW) &&
            S_ISDIR(current.st_mode) && current.st_dev == identity.st_dev &&
            current.st_ino == identity.st_ino && current.st_uid == getuid())
            // Listeners own their socket files. Never sweep unknown contents.
            unlinkat(parent, name.c_str(), AT_REMOVEDIR);
        close(parent);
        parent = -1;
    }

  public:
    std::filesystem::path directory;
    explicit PrivateSocketDirectory(const std::filesystem::path &runtime) {
        if (!runtime.is_absolute())
            throw std::runtime_error("Private socket runtime must be absolute");
        parent = open(runtime.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        struct stat base{};
        if (parent < 0 || fstat(parent, &base) || base.st_uid != getuid() ||
            (base.st_mode & 0077)) {
            cleanup();
            throw std::runtime_error("Private socket runtime must be owned by you and private");
        }
        auto pattern = (runtime / "o-XXXXXX").string();
        if ((pattern + "/s").size() >= sizeof(sockaddr_un::sun_path)) {
            cleanup();
            throw std::runtime_error("Private socket runtime path is too long");
        }
        std::vector<char> writable(pattern.begin(), pattern.end());
        writable.push_back('\0');
        if (!mkdtemp(writable.data())) {
            cleanup();
            throw std::runtime_error("Cannot create private socket directory");
        }
        directory = writable.data();
        name = directory.filename().string();
        struct stat named_base{}, named_directory{};
        if (fstatat(parent, name.c_str(), &identity, AT_SYMLINK_NOFOLLOW) ||
            lstat(runtime.c_str(), &named_base) || lstat(directory.c_str(), &named_directory) ||
            !S_ISDIR(identity.st_mode) || identity.st_uid != getuid() ||
            (identity.st_mode & 0777) != 0700 || base.st_dev != named_base.st_dev ||
            base.st_ino != named_base.st_ino || identity.st_dev != named_directory.st_dev ||
            identity.st_ino != named_directory.st_ino) {
            cleanup();
            throw std::runtime_error("Private socket runtime changed during creation");
        }
    }
    PrivateSocketDirectory(const PrivateSocketDirectory &) = delete;
    PrivateSocketDirectory &operator=(const PrivateSocketDirectory &) = delete;
    ~PrivateSocketDirectory() { cleanup(); }
};
} // namespace traverse
