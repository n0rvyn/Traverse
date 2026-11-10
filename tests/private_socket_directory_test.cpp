#include "private_socket_directory.hpp"
#include <cstring>
#include <fstream>
#include <iostream>
#include <sys/socket.h>

using traverse::PrivateSocketDirectory;
namespace fs = std::filesystem;
static void require(bool value, const char *message) {
    if (!value)
        throw std::runtime_error(message);
}
static void bind_socket(const fs::path &path) {
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    require(path.string().size() < sizeof(address.sun_path), "Test socket path too long");
    std::strcpy(address.sun_path, path.c_str());
    int descriptor = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    require(descriptor >= 0, "Cannot create test socket");
    int result = bind(descriptor, reinterpret_cast<sockaddr *>(&address), sizeof(address));
    close(descriptor);
    require(!result, "Actual private Unix bind failed");
}
int main() {
    char pattern[] = "/tmp/traverse-sockets-XXXXXX";
    const char *created = mkdtemp(pattern);
    if (!created)
        return 1;
    const fs::path root(created);
    try {
        fs::path runtime = root / std::string(70 - root.string().size() - 1, 'r');
        fs::create_directory(runtime);
        fs::permissions(runtime, fs::perms::owner_all);
        const auto old = runtime / ("instance-" + std::string(32, '0')) / "s";
        require(old.string().size() == 114, "Old failing path was not reproduced");
        require((runtime / "adapter.sock").string().size() < sizeof(sockaddr_un::sun_path),
                "Prior adapter path must fit");
        fs::path owned;
        {
            PrivateSocketDirectory first(runtime), second(runtime);
            owned = first.directory;
            require(first.directory != second.directory, "Instances share a socket directory");
            struct stat metadata{};
            require(!lstat(owned.c_str(), &metadata) && (metadata.st_mode & 0777) == 0700 &&
                        metadata.st_uid == getuid(), "Socket directory is not private");
            for (const char *name : {"s", "v", "a"}) {
                bind_socket(owned / name);
                require(!unlink((owned / name).c_str()), "Cannot retire owned test socket");
            }
        }
        require(!fs::exists(owned), "Empty owned socket directory was not removed");
        // Linux permits 107 pathname bytes. Preserve the longest runtime base
        // accepted by the existing thirteen-byte /adapter.sock suffix as well.
        const auto longest = root / std::string(94 - root.string().size() - 1, 'm');
        fs::create_directory(longest);
        fs::permissions(longest, fs::perms::owner_all);
        require((longest / "adapter.sock").string().size() == 107,
                "Prior maximum adapter path was not exercised");
        {
            PrivateSocketDirectory sockets(longest);
            for (const char *name : {"s", "v", "a"}) {
                bind_socket(sockets.directory / name);
                require(!unlink((sockets.directory / name).c_str()), "Cannot retire boundary socket");
            }
        }
        {
            PrivateSocketDirectory sockets(runtime);
            owned = sockets.directory;
            bind_socket(owned / "s");
            std::ofstream(owned / "foreign") << "preserve";
        }
        require(fs::is_socket(owned / "s") && fs::exists(owned / "foreign"),
                "Destructor removed contents it does not own");
        fs::path moved;
        {
            PrivateSocketDirectory sockets(runtime);
            owned = sockets.directory;
            moved = owned.string() + "-moved";
            fs::rename(owned, moved);
            fs::create_directory(owned);
            std::ofstream(owned / "replacement") << "preserve";
        }
        require(fs::exists(moved) && fs::exists(owned / "replacement"),
                "Destructor removed a replacement directory");
        {
            PrivateSocketDirectory sockets(runtime);
            owned = sockets.directory;
            fs::rename(runtime, root / "old-runtime");
            fs::create_directory(runtime);
            fs::create_directory(runtime / owned.filename());
            std::ofstream(runtime / owned.filename() / "replacement") << "preserve";
        }
        require(!fs::exists(root / "old-runtime" / owned.filename()) &&
                    fs::exists(owned / "replacement"), "Cleanup followed a replaced parent path");
        fs::permissions(runtime, fs::perms::all);
        bool refused = false;
        try { PrivateSocketDirectory unsafe(runtime); }
        catch (const std::runtime_error &) { refused = true; }
        require(refused, "Non-private runtime was accepted");
        fs::remove_all(root);
        std::cout << "Private long-path binds, isolation and identity-preserving cleanup passed\n";
        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        fs::remove_all(root);
        return 1;
    }
}
