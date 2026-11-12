#include <libei.h>
#include <libeis.h>
#include <cerrno>
#include <chrono>
#include <fcntl.h>
#include <iostream>
#include <memory>
#include <poll.h>
#include <stdexcept>
#include <sys/socket.h>
#include <unistd.h>

extern "C" void eis_probe_arm_failure(int);
extern "C" int eis_probe_failure_count(void);
int eis_test_server(int control);
static void require(bool ok, const char *message) {
    if (!ok) throw std::runtime_error(message);
}
template<class T, auto Unref> struct Drop {
    void operator()(T *value) const { if (value) Unref(value); }
};
template<class T, auto Unref> using Owned = std::unique_ptr<T, Drop<T, Unref>>;

static void failed_setup() {
    int sockets[2];
    require(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, sockets) == 0,
            "socketpair failed");
    Owned<ei, ei_unref> client(ei_new_sender(nullptr));
    eis_probe_arm_failure(sockets[0]);
    int result = ei_setup_backend_fd(client.get(), sockets[0]);
    client.reset();
    errno = 0;
    bool closed = fcntl(sockets[0], F_GETFD) == -1 && errno == EBADF;
    if (!closed) close(sockets[0]);
    close(sockets[1]);
    require(result == -ENOSPC && eis_probe_failure_count() == 1,
            "exact socket registration failure was not exercised");
    require(closed, "libei leaked its consumed socket after failed setup");
}

static void wire() {
    Owned<eis, eis_unref> server(eis_new(nullptr));
    Owned<ei, ei_unref> client(ei_new_sender(nullptr));
    require(server && client, "context allocation failed");
    require(eis_setup_backend_fd(server.get()) == 0, "server setup failed");
    int fd = eis_backend_fd_add_client(server.get());
    require(fd >= 0, "client socket failed");
    require(ei_setup_backend_fd(client.get(), fd) == 0, "client setup failed");
    Owned<eis_device, eis_device_unref> device;
    bool motion = false, frame = false, sent = false, disconnected = false;
    auto end = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (!disconnected && std::chrono::steady_clock::now() < end) {
        eis_dispatch(server.get());
        while (auto *raw = eis_get_event(server.get())) {
            Owned<eis_event, eis_event_unref> event(raw);
            switch (eis_event_get_type(raw)) {
            case EIS_EVENT_CLIENT_CONNECT: {
                auto *peer = eis_event_get_client(raw);
                require(eis_client_is_sender(peer), "unexpected receiver");
                eis_client_connect(peer);
                Owned<eis_seat, eis_seat_unref> seat(eis_client_new_seat(peer, "probe"));
                eis_seat_configure_capability(seat.get(), EIS_DEVICE_CAP_POINTER_ABSOLUTE);
                eis_seat_add(seat.get());
                break;
            }
            case EIS_EVENT_SEAT_BIND: {
                if (!eis_event_seat_has_capability(raw, EIS_DEVICE_CAP_POINTER_ABSOLUTE)) {
                    require(frame, "pointer capability was withdrawn before the input frame");
                    break;
                }
                require(!device, "duplicate pointer seat binding");
                device.reset(eis_seat_new_device(eis_event_get_seat(raw)));
                eis_device_configure_name(device.get(), "probe pointer");
                eis_device_configure_capability(device.get(), EIS_DEVICE_CAP_POINTER_ABSOLUTE);
                Owned<eis_region, eis_region_unref> region(eis_device_new_region(device.get()));
                eis_region_set_mapping_id(region.get(), "probe-region");
                eis_region_set_size(region.get(), 800, 600);
                eis_region_set_offset(region.get(), 0, 0);
                eis_region_add(region.get());
                eis_device_add(device.get());
                eis_device_resume(device.get());
                break;
            }
            case EIS_EVENT_POINTER_MOTION_ABSOLUTE:
                require(!motion && eis_event_pointer_get_absolute_x(raw) == 123.0 &&
                        eis_event_pointer_get_absolute_y(raw) == 234.0, "wrong absolute coordinates");
                motion = true;
                break;
            case EIS_EVENT_FRAME:
                require(motion && !frame, "missing or duplicate input frame");
                frame = true;
                ei_disconnect(client.get());
                break;
            case EIS_EVENT_CLIENT_DISCONNECT:
                disconnected = true;
                eis_client_disconnect(eis_event_get_client(raw));
                break;
            default: break;
            }
        }
        ei_dispatch(client.get());
        while (auto *raw = ei_get_event(client.get())) {
            Owned<ei_event, ei_event_unref> event(raw);
            switch (ei_event_get_type(raw)) {
            case EI_EVENT_SEAT_ADDED:
                ei_seat_bind_capabilities(ei_event_get_seat(raw), EI_DEVICE_CAP_POINTER_ABSOLUTE, nullptr);
                break;
            case EI_EVENT_DEVICE_RESUMED: {
                require(!sent, "duplicate resumed device");
                auto *pointer = ei_event_get_device(raw);
                ei_device_start_emulating(pointer, 1);
                ei_device_pointer_motion_absolute(pointer, 123.0, 234.0);
                ei_device_frame(pointer, 1);
                sent = true;
                break;
            }
            default: break;
            }
        }
        if (!disconnected) {
            pollfd fds[] = {{eis_get_fd(server.get()), POLLIN, 0}, {ei_get_fd(client.get()), POLLIN, 0}};
            require(poll(fds, 2, 20) >= 0 || errno == EINTR, "poll failed");
        }
    }
    require(sent && motion && frame && disconnected, "native EIS wire sequence incomplete");
}

int main(int argc,char **argv) {
    try {
        if (argc == 3 && std::string(argv[1]) == "--control-fd") {
            std::size_t consumed=0;
            int control=std::stoi(argv[2],&consumed);
            require(consumed == std::string(argv[2]).size() && control >= 0,"Invalid test control fd");
            return eis_test_server(control);
        }
        require(argc == 1,"Unknown provider probe arguments");
        failed_setup();
        wire();
        std::cout << "{\"failedSetupClosed\":true,\"absoluteMotion\":true,\"frame\":true,\"disconnected\":true}\n";
        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
