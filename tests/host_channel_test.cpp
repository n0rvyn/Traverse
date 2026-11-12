#include "host_channel.hpp"
#include <chrono>
#include <csignal>
#include <fcntl.h>
#include <functional>
#include <iostream>
#include <poll.h>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

using traverse::HostAction;
using traverse::HostChannel;
using Json = nlohmann::json;
static void require(bool condition, const char *message) {
    if (!condition)
        throw std::runtime_error(message);
}
static void write_all(int fd, const std::string &value) {
    size_t offset = 0;
    while (offset < value.size()) {
        auto count = send(fd, value.data() + offset, value.size() - offset, MSG_NOSIGNAL);
        require(count > 0, "Fixture write failed");
        offset += static_cast<size_t>(count);
    }
}
static std::string read_bytes(int fd, size_t count) {
    std::string value(count, '\0');
    size_t offset = 0;
    while (offset < count) {
        pollfd event{fd, POLLIN, 0};
        require(poll(&event, 1, 4000) > 0, "Fixture response timed out");
        auto length = read(fd, value.data() + offset, count - offset);
        require(length > 0, "Fixture response closed early");
        offset += static_cast<size_t>(length);
    }
    return value;
}
// Independent wire encoder/decoder; never use the production framing helper.
static std::string frame(const std::string &body) {
    auto size = static_cast<std::uint32_t>(body.size());
    return std::string{static_cast<char>(size >> 24), static_cast<char>(size >> 16),
                       static_cast<char>(size >> 8), static_cast<char>(size)} +
           body;
}
static Json read_json(int fd) {
    auto header = read_bytes(fd, 4);
    std::uint32_t size = 0;
    for (unsigned char byte : header)
        size = (size << 8) | byte;
    return Json::parse(read_bytes(fd, size));
}
static std::string command(unsigned id, const char *action) {
    return frame(Json{{"schemaVersion", 1}, {"requestId", id}, {"action", action}}.dump());
}
static void eventually(const std::function<bool()> &condition) {
    auto until = std::chrono::steady_clock::now() + std::chrono::seconds(4);
    while (!condition()) {
        require(std::chrono::steady_clock::now() < until, "Owned channel transition timed out");
        usleep(1000);
    }
}
static void scenario(const std::function<void(int, int, pid_t)> &child,
                     const std::function<void(int, int, pid_t)> &parent) {
    int data[2], control[2];
    require(!socketpair(AF_UNIX, SOCK_STREAM, 0, data), "Fixture socketpair failed");
    require(!socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, control),
            "Control socketpair failed");
    int small = 4096;
    require(!setsockopt(data[1], SOL_SOCKET, SO_SNDBUF, &small, sizeof(small)),
            "Fixture send buffer failed");
    auto owner = getpid(), pid = fork();
    require(pid >= 0, "Fixture fork failed");
    if (!pid) {
        close(data[0]);
        close(control[0]);
        try {
            child(data[1], control[1], owner);
            _exit(0);
        } catch (const std::exception &error) {
            std::cerr << error.what() << '\n';
            _exit(1);
        }
    }
    close(data[1]);
    close(control[1]);
    bool reaped = false;
    try {
        parent(data[0], control[0], pid);
        int status;
        eventually([&] {
            auto result = waitpid(pid, &status, WNOHANG);
            if (result == pid)
                reaped = true;
            return reaped;
        });
        require(WIFEXITED(status) && WEXITSTATUS(status) == 0, "Owned channel child failed");
    } catch (...) {
        if (!reaped) {
            kill(pid, SIGKILL);
            waitpid(pid, nullptr, 0);
        }
        close(data[0]);
        close(control[0]);
        throw;
    }
    close(data[0]);
    close(control[0]);
}

int main(int argc, char **argv) {
    if (argc == 3 && std::string(argv[1]) == "--closed-fd")
        return fcntl(std::stoi(argv[2]), F_GETFD) == -1 && errno == EBADF ? 0 : 1;
    try {
        HostChannel absent;
        require(!absent.enabled() && absent.receive().empty(), "Ordinary CLI acquired an owner");
        scenario(
            [](int fd, int control, pid_t parent) {
                HostChannel owner(fd, parent);
                require(fcntl(fd, F_GETFD) & FD_CLOEXEC, "Owner descriptor is inheritable");
                auto exec_child = fork();
                require(exec_child >= 0, "Exec witness fork failed");
                if (!exec_child) {
                    auto number = std::to_string(fd);
                    execl("/proc/self/exe", "host-channel-test", "--closed-fd", number.c_str(),
                          nullptr);
                    _exit(2);
                }
                int status;
                require(waitpid(exec_child, &status, 0) == exec_child && WIFEXITED(status) &&
                            WEXITSTATUS(status) == 0,
                        "Owner descriptor survived exec");
                write_all(control, "r");
                require(read_bytes(control, 1) == "1", "Fragment handshake failed");
                require(owner.receive().empty() && !owner.failed(),
                        "Partial header became a command");
                owner.send({{"stage", 1}});
                require(read_bytes(control, 1) == "2", "Payload handshake failed");
                require(owner.receive().empty() && !owner.failed(),
                        "Partial body became a command");
                owner.send({{"stage", 2}});
                require(read_bytes(control, 1) == "3", "Coalescing handshake failed");
                std::vector<traverse::HostCommand> received;
                eventually([&] {
                    auto batch = owner.receive();
                    received.insert(received.end(), batch.begin(), batch.end());
                    return received.size() == 4;
                });
                require(received[0].request_id == 10 && received[0].action == HostAction::Status &&
                            received[1].request_id == 11 &&
                            received[1].action == HostAction::NewCode &&
                            received[2].request_id == 12 && received[2].action == HostAction::CheckConnection &&
                            received[3].request_id == 13 && received[3].action == HostAction::Stop,
                        "Fragmented/coalesced commands changed order or identity");
            },
            [](int fd, int control, pid_t) {
                require(read_bytes(control, 1) == "r", "Owner did not initialize");
                auto first = command(10, "status");
                write_all(fd, first.substr(0, 2));
                write_all(control, "1");
                require(read_json(fd).at("stage") == 1, "Partial header acknowledgment missing");
                write_all(fd, first.substr(2, 5));
                write_all(control, "2");
                require(read_json(fd).at("stage") == 2, "Partial body acknowledgment missing");
                write_all(fd, first.substr(7) + command(11, "new-code") + command(12, "check-connection") + command(13, "stop"));
                write_all(control, "3");
            });
        for (auto invalid :
             {R"({"schemaVersion":2,"requestId":1,"action":"status"})",
              R"({"schemaVersion":1,"requestId":-1,"action":"status"})",
              R"({"schemaVersion":1,"requestId":1,"action":"unknown"})",
              R"({"schemaVersion":1,"requestId":1,"action":"status","force":true})",
              R"({"schemaVersion":1,"schemaVersion":1,"requestId":1,"action":"status"})",
              R"({"schemaVersion":1,"requestId":1,"action":{"status":true}})",
              R"({"schemaVersion":1.0,"requestId":1,"action":"status"})", "not-json"}) {
            scenario(
                [](int fd, int control, pid_t parent) {
                    HostChannel owner(fd, parent);
                    write_all(control, "r");
                    eventually([&] {
                        require(owner.receive().empty(), "Malformed command escaped validation");
                        return owner.closed();
                    });
                    require(owner.failed(), "Malformed owner command did not fail closed");
                },
                [&](int fd, int control, pid_t) {
                    require(read_bytes(control, 1) == "r", "Owner did not initialize");
                    write_all(fd, frame(invalid));
                });
        }
        scenario(
            [](int fd, int control, pid_t parent) {
                HostChannel owner(fd, parent);
                owner.send({{"state", std::string(65536, 'x')}});
                require(owner.pending_output(), "Backpressure fixture never blocked output");
                write_all(control, "r");
                eventually([&] {
                    for (auto value : owner.receive())
                        if (value.action == HostAction::Stop)
                            return true;
                    return false;
                });
                require(owner.pending_output(), "Fixture drained the blocked output");
            },
            [](int fd, int control, pid_t) {
                require(read_bytes(control, 1) == "r", "Backpressure was not observed");
                write_all(fd, command(1, "stop"));
            });
        scenario(
            [](int fd, int control, pid_t parent) {
                HostChannel owner(fd, parent);
                write_all(control, "r");
                eventually([&] {
                    require(owner.receive().empty(), "EOF authorized an incomplete command");
                    return owner.closed();
                });
                require(!owner.failed(), "Normal owner EOF became a protocol failure");
            },
            [](int fd, int control, pid_t) {
                require(read_bytes(control, 1) == "r", "Owner did not initialize");
                write_all(fd, std::string("\0\0\0\x40{", 5));
                shutdown(fd, SHUT_WR);
            });
        for (int kind : {0, 1, 2, 3}) {
            scenario(
                [&](int fd, int, pid_t parent) {
                    if (kind == 0) {
                        close(fd);
                        fd = open("/dev/null", O_RDONLY);
                    }
                    if (kind == 1) {
                        close(fd);
                        fd = socket(AF_UNIX, SOCK_STREAM, 0);
                    }
                    if (kind == 3 && getuid() != 0)
                        return;
                    if (kind == 3)
                        require(!setgid(65534) && !setuid(65534), "UID witness setup failed");
                    bool rejected = false;
                    try {
                        HostChannel owner(fd, kind == 2 ? parent + 1 : parent);
                    } catch (const std::exception &) {
                        rejected = true;
                    }
                    require(rejected, "Invalid owner descriptor/parent/UID was accepted");
                },
                [](int, int, pid_t) {});
        }
        scenario(
            [](int fd, int control, pid_t parent) {
                traverse::HostSupervisor owner(fd, parent, "synthetic-instance");
                owner.bind([]() -> Json { throw std::runtime_error("producer unavailable"); });
                write_all(control, "r");
                eventually([&] { return owner.pump(); });
            },
            [](int fd, int control, pid_t) {
                require(read_bytes(control, 1) == "r", "Supervisor did not initialize");
                require(read_json(fd).at("state").at("phase") == "starting",
                        "Initial owner stage missing");
                write_all(fd, command(40, "status") + command(41, "stop"));
                auto reply = read_json(fd);
                require(reply.at("requestId") == 41 && reply.at("ok") == true &&
                            reply.at("phase") == "stopping",
                        "Producer lookup delayed Stop");
            });
        scenario(
            [](int fd,int control,pid_t parent) {
                traverse::HostSupervisor owner(fd,parent,"check-instance");int checks=0;
                owner.bind([&]{return Json{{"checks",checks}};},{},[&]{++checks;return Json{{"ok",true}};});
                write_all(control,"r");eventually([&]{return owner.pump();});
                require(checks==1,"Private connection action did not reach callback");
            },
            [](int fd,int control,pid_t) {
                require(read_bytes(control,1)=="r","Connection supervisor missing");read_json(fd);
                write_all(fd,command(50,"check-connection"));auto reply=read_json(fd);
                require(reply.at("requestId")==50 && reply.at("ok")==true && reply.at("state").at("checks")==1,
                    "Connection check acknowledgement/state missing");
                write_all(fd,command(51,"stop"));require(read_json(fd).at("requestId")==51,"Stop reply missing");
            });
        scenario(
            [](int fd,int control,pid_t parent) {
                traverse::HostSupervisor owner(fd,parent,"export-instance");int exports=0;
                owner.bind([&]{return Json{{"exports",exports}};},{},{},[&]{++exports;return Json{{"ok",true},{"publicCA",{{"publicOnly",true}}}};});
                write_all(control,"r");eventually([&]{return owner.pump();});
                require(exports==1,"Export callback count changed or Stop lost priority");
            },
            [](int fd,int control,pid_t) {
                require(read_bytes(control,1)=="r","Export supervisor missing");auto initial=read_json(fd);
                require(!initial.contains("publicCA"),"Public PEM entered periodic state");
                write_all(fd,command(60,"export-ca"));auto reply=read_json(fd);
                require(reply.at("requestId")==60&&reply.at("ok")==true&&reply.at("publicCA").at("publicOnly")==true&&reply.at("state").at("exports")==1,
                    "Private public export reply/correlation missing");
                write_all(fd,command(61,"export-ca")+command(62,"stop"));
                require(read_json(fd).at("requestId")==62,"Export callback delayed Stop");
            });
        std::cout
            << "Host framing, private identity, exec isolation, backpressure Stop and EOF passed\n";
        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
