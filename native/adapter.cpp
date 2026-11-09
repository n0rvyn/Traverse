#include "common.hpp"
#include <X11/Xlib.h>
#include <fcntl.h>
#include <poll.h>
#include <spawn.h>
#include <sys/file.h>
#include <sys/prctl.h>
#include <sys/un.h>
#include <sys/wait.h>
extern char **environ;

// An exclusive owner lock distinguishes a dead adapter's socket from a live one.
class SocketOwner {
    int lock_fd = -1;

  public:
    explicit SocketOwner(const std::string &path) {
        lock_fd = open((path + ".lock").c_str(), O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (lock_fd < 0)
            throw std::runtime_error("Cannot open adapter owner lock");
        if (flock(lock_fd, LOCK_EX | LOCK_NB) != 0) {
            close(lock_fd);
            lock_fd = -1;
            throw std::runtime_error("Another adapter owns this control socket");
        }
    }
    ~SocketOwner() {
        if (lock_fd >= 0)
            close(lock_fd);
    }
    static void clear_stale(const std::string &path) {
        struct stat info{};
        if (lstat(path.c_str(), &info) != 0) {
            if (errno == ENOENT)
                return;
            throw std::runtime_error("Cannot inspect socket path");
        }
        if (!S_ISSOCK(info.st_mode) || info.st_uid != getuid())
            throw std::runtime_error("Existing path is not an owned socket");
        int probe = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (probe < 0)
            throw std::runtime_error("Cannot inspect old socket");
        sockaddr_un address{};
        address.sun_family = AF_UNIX;
        if (path.size() >= sizeof(address.sun_path)) {
            close(probe);
            throw std::runtime_error("Socket path too long");
        }
        std::copy(path.begin(), path.end(), address.sun_path);
        int connected = connect(probe, reinterpret_cast<sockaddr *>(&address), sizeof(address));
        int error = errno;
        close(probe);
        if (connected == 0 || (error != ECONNREFUSED && error != ENOENT))
            throw std::runtime_error("Existing socket is live or cannot be proven stale");
        if (unlink(path.c_str()) != 0 && errno != ENOENT)
            throw std::runtime_error("Cannot remove owned stale socket");
    }
};
class Worker {
    int fd = -1;
    pid_t pid = -1;
    std::mutex mutex;

  public:
    explicit Worker(const std::string &display) {
        int sockets[2];
        if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets))
            throw std::runtime_error("socketpair failed");
        pid = fork();
        if (pid < 0)
            throw std::runtime_error("fork failed");
        if (pid == 0) {
            dup2(sockets[1], STDIN_FILENO);
            close(sockets[0]);
            close(sockets[1]);
            execl("/proc/self/exe", "traverse-adapter", "--input-worker", "--display",
                  display.c_str(), nullptr);
            _exit(127);
        }
        close(sockets[1]);
        fd = sockets[0];
    }
    void call(const json &e) {
        std::lock_guard lock(mutex);
        auto message = e.dump() + "\n";
        size_t offset = 0;
        while (offset < message.size()) {
            ssize_t n = send(fd, message.data() + offset, message.size() - offset, MSG_NOSIGNAL);
            if (n <= 0)
                throw std::runtime_error("Input guardian unavailable");
            offset += n;
        }
        std::string line;
        char c;
        while (true) {
            pollfd p{fd, POLLIN, 0};
            if (poll(&p, 1, 2000) <= 0)
                throw std::runtime_error("Input guardian timeout");
            if (read(fd, &c, 1) != 1)
                throw std::runtime_error("Input guardian exited");
            if (c == '\n')
                break;
            line += c;
        }
        auto result = json::parse(line);
        if (!result.value("ok", false))
            throw std::runtime_error(result.value("error", "Invalid input"));
    }
    ~Worker() {
        if (fd >= 0) {
            close(fd);
            fd = -1;
        }
        if (pid > 0) {
            while (waitpid(pid, nullptr, 0) < 0 && errno == EINTR) {
            }
        }
    }
};
class Adapter {
    std::mutex mutex;
    Worker worker;
    std::string display, frame_socket;
    GstElement *pipeline = nullptr;
    pid_t dialog = -1;
    bool no_dialog;
    bool armed = true, paired = false;
    std::string code = random_secret(12), token;
    Clock::time_point code_created = Clock::now(), last_input = Clock::now();
    unsigned long accepted = 0, denied = 0;
    int fps;
    void stop_dialog() {
        if (dialog > 0) {
            kill(dialog, SIGTERM);
            while (waitpid(dialog, nullptr, 0) < 0 && errno == EINTR) {
            }
            dialog = -1;
        }
    }
    void show_dialog() {
        stop_dialog();
        if (no_dialog)
            return;
        auto text = "Traverse sharing\nPairing code: " + code +
                    "\nCode expires in 5 minutes.\nStop sharing disconnects the browser.";
        std::vector<std::string> strings = {
            "traverse-adapter", "--local-dialog", "--parent-pid",  std::to_string(getpid()),
            "--display",        display,          "--dialog-text", text};
        std::vector<char *> args;
        for (auto &s : strings)
            args.push_back(s.data());
        args.push_back(nullptr);
        if (posix_spawn(&dialog, "/proc/self/exe", nullptr, nullptr, args.data(), environ) != 0)
            throw std::runtime_error(
                "Cannot start local stop dialog; use --no-dialog for CLI-only sharing");
    }
    void release() {
        worker.call({{"type", "release"}});
    }
    void revoke_locked() {
        armed = false;
        paired = false;
        token.clear();
        try {
            release();
        } catch (const std::exception &e) {
            std::cerr << e.what() << '\n';
        }
        stop_pipeline(pipeline);
        std::filesystem::remove(frame_socket);
    }
    bool auth(const httplib::Request &r) {
        if (!armed || !paired || !equal_secret(token, bearer(r))) {
            denied++;
            return false;
        }
        return true;
    }
    json state_locked() {
        Display *d = XOpenDisplay(display.c_str());
        if (!d)
            throw std::runtime_error("Display unavailable");
        Window root;
        int x, y;
        unsigned int w, h, b, depth;
        XGetGeometry(d, DefaultRootWindow(d), &root, &x, &y, &w, &h, &b, &depth);
        XCloseDisplay(d);
        return {{"armed", armed},       {"paired", paired}, {"capturing", pipeline != nullptr},
                {"width", w},           {"height", h},      {"frameSocket", frame_socket},
                {"accepted", accepted}, {"denied", denied}};
    }

  public:
    Adapter(std::string name, std::string frames, int rate, bool cli)
        : worker(name), display(std::move(name)), frame_socket(std::move(frames)), no_dialog(cli),
          fps(rate) {
        Display *d = XOpenDisplay(display.c_str());
        if (!d)
            throw std::runtime_error("No existing X11 display at " + display);
        XCloseDisplay(d);
        std::cout << "Pairing code: " << code << std::endl;
        show_dialog();
    }
    ~Adapter() {
        std::lock_guard lock(mutex);
        revoke_locked();
        stop_dialog();
    }
    void routes(httplib::Server &server) {
        server.Post("/pair", [this](const httplib::Request &r, httplib::Response &s) {
            std::lock_guard lock(mutex);
            try {
                auto body = parse_body(r);
                if (!body.is_object() || !body.contains("code") || !body["code"].is_string()) {
                    denied++;
                    reply(s, {{"error", "Pairing code must be text"}}, 400);
                    return;
                }
                auto given = body["code"].get<std::string>();
                if (!armed || paired || Clock::now() - code_created > std::chrono::minutes(5) ||
                    !equal_secret(code, given)) {
                    denied++;
                    reply(s, {{"error", "Pairing code invalid, expired or used"}}, 403);
                    return;
                }
                pipeline = gst_pipeline_new("desktop-capture");
                auto add = [&](const char *factory) {
                    auto *element = gst_element_factory_make(factory, nullptr);
                    if (!element)
                        throw std::runtime_error("Capture plugin unavailable");
                    gst_bin_add(GST_BIN(pipeline), element);
                    return element;
                };
                auto *source = add("ximagesrc");
                auto *convert = add("videoconvert");
                auto *filter = add("capsfilter");
                auto *sink = add("unixfdsink");
                g_object_set(source, "display-name", display.c_str(), "use-damage", FALSE,
                             "show-pointer", TRUE, nullptr);
                GstCaps *caps =
                    gst_caps_new_simple("video/x-raw", "format", G_TYPE_STRING, "I420", "framerate",
                                        GST_TYPE_FRACTION, fps, 1, nullptr);
                g_object_set(filter, "caps", caps, nullptr);
                gst_caps_unref(caps);
                g_object_set(sink, "socket-path", frame_socket.c_str(), "sync", FALSE,
                             "wait-for-connection", TRUE, nullptr);
                if (!gst_element_link_many(source, convert, filter, sink, nullptr))
                    throw std::runtime_error("Capture links failed");
                if (gst_element_set_state(pipeline, GST_STATE_PLAYING) == GST_STATE_CHANGE_FAILURE)
                    throw std::runtime_error("Capture failed");
                gst_element_get_state(pipeline, nullptr, nullptr, GST_SECOND);
                check_bus(pipeline);
                token = random_secret(32);
                paired = true;
                last_input = Clock::now();
                reply(s, {{"token", token}});
            } catch (const std::exception &e) {
                if (pipeline && !paired)
                    revoke_locked();
                reply(s, {{"error", e.what()}}, 400);
            }
        });
        server.Get("/state", [this](const httplib::Request &, httplib::Response &s) {
            std::lock_guard lock(mutex);
            try {
                reply(s, state_locked());
            } catch (const std::exception &e) {
                reply(s, {{"error", e.what()}}, 503);
            }
        });
        server.Post("/input", [this](const httplib::Request &r, httplib::Response &s) {
            std::lock_guard lock(mutex);
            if (!auth(r)) {
                reply(s, {{"error", "Control revoked"}}, 403);
                return;
            }
            try {
                worker.call(parse_body(r));
                last_input = Clock::now();
                accepted++;
                reply(s, {{"ok", true}});
            } catch (const std::exception &e) {
                try {
                    release();
                } catch (...) {
                }
                reply(s, {{"error", e.what()}}, 400);
            }
        });
        server.Post("/revoke", [this](const httplib::Request &, httplib::Response &s) {
            std::lock_guard lock(mutex);
            revoke_locked();
            stop_dialog();
            reply(s, {{"armed", false}});
        });
        server.Post("/arm", [this](const httplib::Request &, httplib::Response &s) {
            std::lock_guard lock(mutex);
            revoke_locked();
            armed = true;
            code = random_secret(12);
            code_created = Clock::now();
            show_dialog();
            std::cout << "Pairing code: " << code << std::endl;
            reply(s, {{"code", code}});
        });
    }
    void tick() {
        std::lock_guard lock(mutex);
        if (dialog > 0 && waitpid(dialog, nullptr, WNOHANG) == dialog) {
            dialog = -1;
            revoke_locked();
        }
        if (pipeline) {
            try {
                check_bus(pipeline);
            } catch (const std::exception &e) {
                std::cerr << "Capture stopped: " << e.what() << '\n';
                revoke_locked();
            }
        }
        if (Clock::now() - last_input > std::chrono::seconds(3)) {
            try {
                release();
            } catch (...) {
                revoke_locked();
            }
        }
    }
};
int main(int argc, char **argv) {
    try {
        XInitThreads();
        Args args(argc, argv);
        guard_supervisor(args);
        auto name = args.get("--display", getenv("DISPLAY") ? getenv("DISPLAY") : ":0");
        if (args.has("--local-dialog")) {
            // Preserve the death signal across exec; also cover death before this helper starts.
            auto parent = static_cast<pid_t>(std::stol(args.get("--parent-pid")));
            if (prctl(PR_SET_PDEATHSIG, SIGTERM) != 0 || getppid() != parent)
                return 1;
            auto text = args.get("--dialog-text");
            execlp("xmessage", "xmessage", "-display", name.c_str(), "-title", "Traverse sharing",
                   "-buttons", "Stop sharing:0", "-default", "Stop sharing", "-geometry", "+850+20",
                   text.c_str(), static_cast<char *>(nullptr));
            throw std::runtime_error("Cannot execute local sharing dialog");
        }
        if (args.has("--input-worker"))
            return input_worker(name);
        auto socket_path = args.get("--socket", default_socket());
        if (args.has("--control")) {
            Ipc ipc(socket_path);
            auto action = args.get("--control");
            json empty = json::object();
            if (action != "state" && action != "arm" && action != "revoke")
                throw std::runtime_error("Invalid local action");
            std::cout << ipc.call("/" + action, action == "state" ? nullptr : &empty).dump(2)
                      << '\n';
            return 0;
        }
        umask(0077);
        std::filesystem::create_directories(std::filesystem::path(socket_path).parent_path());
        SocketOwner owner(socket_path);
        auto frames = args.get("--frames", socket_path + ".frames");
        SocketOwner::clear_stale(socket_path);
        SocketOwner::clear_stale(frames);
        int fps = std::stoi(args.get("--fps", "60"));
        if (fps <= 0)
            throw std::runtime_error("fps must be positive");
        // Start the independent worker before GStreamer creates any threads.
        Adapter adapter(name, frames, fps, args.has("--no-dialog"));
        gst_init(nullptr, nullptr);
        std::signal(SIGINT, signal_stop);
        std::signal(SIGTERM, signal_stop);
        std::signal(SIGPIPE, SIG_IGN);
        httplib::Server server;
        adapter.routes(server);
        server.set_address_family(AF_UNIX);
        if (!server.bind_to_port(socket_path, 80))
            throw std::runtime_error("Cannot bind adapter socket");
        chmod(socket_path.c_str(), 0600);
        std::thread listener([&] { server.listen_after_bind(); });
        while (!stopping) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            adapter.tick();
        }
        server.stop();
        listener.join();
        std::filesystem::remove(socket_path);
        return 0;
    } catch (const std::exception &e) {
        std::cerr << "Adapter: " << e.what() << '\n';
        return 1;
    }
}
