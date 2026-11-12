#include "child.hpp"
#include <cerrno>
#include <sys/syscall.h>

static void require(bool condition, const char *message) {
    if (!condition)
        throw std::runtime_error(message);
}
static int fixture(int argc, char **argv) {
    if (argc != 3 || std::string(argv[1]) != "--supervisor-pid")
        return 90;
    auto parent = std::stol(argv[2]);
    if (prctl(PR_SET_PDEATHSIG, SIGTERM) || getppid() != parent)
        return 91;
    std::string input((std::istreambuf_iterator<char>(std::cin)), {});
    auto request = json::parse(input);
    require(request.at("owner").get<pid_t>() == getppid(), "Operation arguments changed owner");
    auto mode = request.at("mode").get<std::string>();
    if (mode == "hold" || mode == "ignore-term") {
        if(mode == "ignore-term")signal(SIGTERM,SIG_IGN);
        std::cout << "pending\n" << std::flush;
        std::ofstream ready(request.at("ready").get<std::string>());
        ready << "ready";
        ready.close();
        while (true)
            pause();
    }
    if (mode == "early-exit")
        return 7;
    if (mode == "malformed") {
        std::cout << "not-json" << std::flush;
        return 0;
    }
    json result = {{"version", 1},
                   {"status", mode == "success" ? "ready" : "failed"},
                   {"echo", request.at("payload")}};
    std::cout << result.dump() << '\n' << std::flush;
    return mode == "success" ? 0 : 2;
}
static OwnedOperation::Result finish(OwnedOperation &operation) {
    auto deadline = Clock::now() + std::chrono::seconds(5);
    while (Clock::now() < deadline) {
        if (auto result = operation.poll())
            return *result;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    throw std::runtime_error("Owned operation did not finish");
}
static void ready(OwnedOperation &operation, const std::filesystem::path &path) {
    auto deadline = Clock::now() + std::chrono::seconds(3);
    while (!std::filesystem::exists(path)) {
        require(!operation.poll(), "Pending child exited early");
        require(Clock::now() < deadline, "Pending child did not acknowledge request");
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}
int main(int argc, char **argv) {
    if (argc > 1)
        return fixture(argc, argv);
    try {
        auto binary = std::filesystem::canonical(argv[0]);
        for (const auto &mode : {"success", "failure", "malformed", "early-exit"}) {
            json request = {
                {"owner", getpid()}, {"mode", mode}, {"payload", std::string(1024 * 1024, 'p')}};
            OwnedOperation operation(binary, request.dump());
            auto result = finish(operation);
            if (std::string(mode) == "malformed")
                require(result.output == "not-json", "Malformed result was silently normalized");
            else if (std::string(mode) == "early-exit")
                require(result.exit_status == 7 && result.output.empty(),
                        "Early child exit disappeared");
            else {
                auto decoded = json::parse(result.output);
                require(decoded.at("echo") == request.at("payload"),
                        "Partial inherited request/result bytes lost");
                require(result.exit_status == (std::string(mode) == "success" ? 0 : 2),
                        "One-shot exit treated as daemon failure");
            }
            require(operation.id() == -1, "Completed operation was not reaped");
        }
        auto directory =
            std::filesystem::temp_directory_path() / ("traverse-operation-" + random_secret(8));
        require(std::filesystem::create_directory(directory), "Cannot create owned fixture state");
        struct Cleanup {
            std::filesystem::path path;
            ~Cleanup() {
                std::error_code ignored;
                std::filesystem::remove_all(path, ignored);
            }
        } cleanup{directory};
        auto marker = directory / "cancel-ready";
        {
            auto slow_marker=directory/"slow-ready";
            OwnedOperation operation(binary,json{{"owner",getpid()},{"mode","ignore-term"},
                {"ready",slow_marker.string()}}.dump());
            auto pid=operation.id();ready(operation,slow_marker);
            operation.poll();
            require(operation.accumulated_output()=="pending\n","Streaming output unavailable before completion");
            auto started=Clock::now();operation.request_stop();operation.request_stop();
            require(Clock::now()-started<std::chrono::milliseconds(100),"Cancellation blocked supervisor");
            require(!operation.poll() && operation.id()==pid,"Cancellation failed to preserve live child for reaping");
            auto watchdog=started+std::chrono::seconds(8);
            std::optional<OwnedOperation::Result> result;
            while(!(result=operation.poll())) {
                require(Clock::now()<watchdog,"Ignoring child survived cancellation grace");
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            require(result->exit_status==128+SIGKILL && result->output=="pending\n","Cancelled operation lost output or exit status");
            require(Clock::now()-started>=std::chrono::seconds(5),"Existing cancellation grace shortened");
            errno=0;require(waitpid(pid,nullptr,WNOHANG)==-1 && errno==ECHILD,"Asynchronously cancelled child not reaped");
        }
        {
            OwnedOperation operation(
                binary,
                json{{"owner", getpid()}, {"mode", "hold"}, {"ready", marker.string()}}.dump());
            auto pid = operation.id();
            ready(operation, marker);
            operation.stop();
            require(operation.id() == -1, "Cancelled operation retained PID");
            errno = 0;
            require(waitpid(pid, nullptr, WNOHANG) == -1 && errno == ECHILD,
                    "Cancelled child was not reaped");
        }
        int channel[2];
        require(pipe2(channel, O_CLOEXEC) == 0, "Cannot create owner-death witness");
        auto driver = fork();
        require(driver >= 0, "Cannot start owned driver");
        if (!driver) {
            close(channel[0]);
            try {
                auto marker = directory / "death-ready";
                OwnedOperation operation(
                    binary,
                    json{{"owner", getpid()}, {"mode", "hold"}, {"ready", marker.string()}}.dump());
                ready(operation, marker);
                auto pid = operation.id();
                if (write(channel[1], &pid, sizeof(pid)) != sizeof(pid))
                    _exit(93);
                _exit(0); // Deliberately bypass destructor to exercise PDEATHSIG.
            } catch (...) {
                _exit(94);
            }
        }
        close(channel[1]);
        pid_t child = -1;
        auto bytes = read(channel[0], &child, sizeof(child));
        close(channel[0]);
        int driver_status = 0;
        require(waitpid(driver, &driver_status, 0) == driver && WIFEXITED(driver_status) &&
                    WEXITSTATUS(driver_status) == 0,
                "Owned driver failed");
        require(bytes == sizeof(child) && child > 0, "Parent-death child identity absent");
        int descriptor = syscall(SYS_pidfd_open, child, 0);
        if (descriptor >= 0) {
            pollfd item{descriptor, POLLIN, 0};
            auto result = ::poll(&item, 1, 3000);
            if (result <= 0)
                syscall(SYS_pidfd_send_signal, descriptor, SIGKILL, nullptr, 0);
            close(descriptor);
            require(result > 0, "Operation survived its owner");
        } else
            require(errno == ESRCH, "Cannot inspect owner-death child");
        bool rejected = false;
        try {
            OwnedOperation absent(directory / "not-an-executable", "{}");
        } catch (const std::exception &) {
            rejected = true;
        }
        require(rejected, "Spawn failure was hidden");
        std::cout << "Owned operations: actual pipes, backpressure, exit, cancellation and parent "
                     "death passed\n";
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
