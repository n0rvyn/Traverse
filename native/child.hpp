#pragma once
#include "common.hpp"
#include <fcntl.h>
#include <poll.h>
#include <spawn.h>
#include <sys/wait.h>
extern char **environ;

// Only unreaped children created here can be signalled. No PID-file signalling.
class Child {
    pid_t pid = -1;
    int output = -1;
    std::string name, pending;

  public:
    Child(const std::filesystem::path &binary, std::vector<std::string> arguments,
          bool capture_ready = false) : name(binary.filename()) {
        arguments.insert(arguments.begin(), binary.string());
        arguments.push_back("--supervisor-pid");
        arguments.push_back(std::to_string(getpid()));
        std::vector<char *> argv;
        for (auto &argument : arguments)
            argv.push_back(argument.data());
        argv.push_back(nullptr);
        int descriptors[2] = {-1, -1};
        posix_spawn_file_actions_t actions;
        posix_spawn_file_actions_t *options = nullptr;
        if (capture_ready) {
            int original[2];
            if (pipe2(original, O_CLOEXEC))
                throw std::runtime_error("Cannot create child readiness pipe");
            descriptors[0] = fcntl(original[0], F_DUPFD_CLOEXEC, 3);
            descriptors[1] = fcntl(original[1], F_DUPFD_CLOEXEC, 3);
            close(original[0]);close(original[1]);
            int error = descriptors[0] < 0 || descriptors[1] < 0
                            ? errno : posix_spawn_file_actions_init(&actions);
            if (!error) {
                options = &actions;
                error = posix_spawn_file_actions_adddup2(&actions, descriptors[1], STDOUT_FILENO);
                if (!error) error = posix_spawn_file_actions_addclose(&actions, descriptors[0]);
                if (!error) error = posix_spawn_file_actions_addclose(&actions, descriptors[1]);
            }
            if (error) {
                if (options) posix_spawn_file_actions_destroy(options);
                if (descriptors[0] >= 0) close(descriptors[0]);
                if (descriptors[1] >= 0) close(descriptors[1]);
                throw std::runtime_error("Cannot prepare child readiness pipe");
            }
        }
        int result = posix_spawn(&pid, binary.c_str(), options, nullptr, argv.data(), environ);
        if (options) posix_spawn_file_actions_destroy(options);
        if (descriptors[1] >= 0) close(descriptors[1]);
        if (result) {
            pid = -1;
            if (descriptors[0] >= 0) close(descriptors[0]);
            throw std::runtime_error("Cannot start " + name + ": " + std::strerror(result));
        }
        output = descriptors[0];
    }
    Child(const Child &) = delete;
    Child &operator=(const Child &) = delete;
    pid_t id() const { return pid; }
    void check() {
        if (pid <= 0)
            throw std::runtime_error(name + " is no longer running");
        int status;
        pid_t result = waitpid(pid, &status, WNOHANG);
        if (result == pid) {
            pid = -1;
            throw std::runtime_error(name + " exited; sharing has stopped");
        }
        if (result < 0 && errno != EINTR)
            throw std::runtime_error("Cannot monitor " + name);
    }
    std::string ready_line() {
        if (output < 0)
            throw std::runtime_error("Child readiness pipe unavailable");
        auto deadline = Clock::now() + std::chrono::seconds(15);
        while (!stopping && Clock::now() < deadline) {
            check();
            pollfd item{output, POLLIN, 0};
            int ready = poll(&item, 1, 100);
            if (ready < 0 && errno != EINTR)
                throw std::runtime_error("Cannot inspect " + name + " readiness");
            if (ready <= 0) continue;
            char bytes[1024];
            auto count = read(output, bytes, sizeof(bytes));
            if (count <= 0)
                throw std::runtime_error(name + " closed its readiness pipe");
            pending.append(bytes, count);
            auto end = pending.find('\n');
            if (end != std::string::npos) {
                close(output);output = -1;
                return pending.substr(0, end);
            }
        }
        throw std::runtime_error(name + " did not become ready");
    }
    void stop() noexcept {
        if (pid > 0) {
            kill(pid, SIGTERM);
            auto deadline = Clock::now() + std::chrono::seconds(5);
            while (Clock::now() < deadline) {
                auto result = waitpid(pid, nullptr, WNOHANG);
                if (result == pid || (result < 0 && errno == ECHILD)) {
                    pid = -1;
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(20));
            }
            if (pid > 0) {
                kill(pid, SIGKILL);
                while (waitpid(pid, nullptr, 0) < 0 && errno == EINTR) {}
                pid = -1;
            }
        }
        if (output >= 0) { close(output);output = -1; }
    }
    ~Child() { stop(); }
};
