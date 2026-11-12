// Internal provider calibration only: explicit synthetic daemon socket, no media.
#include <gst/gst.h>
#include <pipewire/pipewire.h>
#include <nlohmann/json.hpp>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <set>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
using Json = nlohmann::json;
namespace {
struct Observation {
    pw_main_loop *loop;
    int sequence = -1, error = 0;
    bool completed = false, watchdog = false;
};
struct PipeWireInit {
    PipeWireInit() { pw_init(nullptr, nullptr); }
    ~PipeWireInit() { pw_deinit(); }
};
const pw_core_events events = [] {
    pw_core_events result{};
    result.version = PW_VERSION_CORE_EVENTS;
    result.done = +[](void *data, uint32_t id, int sequence) {
        auto &state = *static_cast<Observation *>(data);
        if (id == PW_ID_CORE && sequence == state.sequence) {
            state.completed = true;
            pw_main_loop_quit(state.loop);
        }
    };
    result.error = +[](void *data, uint32_t id, int, int error, const char *) {
        auto &state = *static_cast<Observation *>(data);
        if (id == PW_ID_CORE) { state.error = error; pw_main_loop_quit(state.loop); }
    };
    return result;
}();
std::set<std::string> loaded_providers() {
    std::set<std::string> result;
    std::ifstream maps("/proc/self/maps");
    std::string line;
    while (std::getline(maps, line)) {
        auto start = line.find('/');
        if (start == std::string::npos) continue;
        auto path = line.substr(start);
        if (path.find("/libpipewire-") != std::string::npos || path.find("/libspa-") != std::string::npos)
            result.insert(std::move(path));
    }
    return result;
}
}
int main(int argc, char **argv) {
    Json report{{"connected", false}, {"mediaOrInputRequested", false}, {"uid", getuid()}};
    try {
        if (argc != 3) throw std::runtime_error("Usage: pipewire-provider-probe PLUGIN_FILE SYNTHETIC_SOCKET");
        gst_init(nullptr, nullptr);
        GError *error = nullptr;
        std::unique_ptr<GstPlugin, decltype(&gst_object_unref)> plugin(
            gst_plugin_load_file(argv[1], &error), gst_object_unref);
        if (!plugin) {
            std::string message = error ? error->message : "PipeWire plugin unavailable";
            g_clear_error(&error); throw std::runtime_error(message);
        }
        report["pluginVersion"] = gst_plugin_get_version(plugin.get());
        report["pluginFile"] = gst_plugin_get_filename(plugin.get());
        std::unique_ptr<GstElement, decltype(&gst_object_unref)> source(
            gst_element_factory_make("pipewiresrc", nullptr), gst_object_unref);
        if (!source) throw std::runtime_error("PipeWire capture factory unavailable");
        std::unique_ptr<GstPlugin, decltype(&gst_object_unref)> source_plugin(
            gst_plugin_feature_get_plugin(GST_PLUGIN_FEATURE(gst_element_get_factory(source.get()))), gst_object_unref);
        if (!source_plugin || source_plugin.get() != plugin.get())
            throw std::runtime_error("Capture factory belongs to a different provider");
        for (const char *name : {"fd", "path", "target-object", "stream-properties", "always-copy"})
            if (!g_object_class_find_property(G_OBJECT_GET_CLASS(source.get()), name))
                throw std::runtime_error(std::string("PipeWire source property unavailable: ") + name);
        PipeWireInit initialized;
        report["clientLibraryVersion"] = pw_get_library_version();
        std::unique_ptr<pw_main_loop, decltype(&pw_main_loop_destroy)> loop(pw_main_loop_new(nullptr), pw_main_loop_destroy);
        if (!loop) throw std::runtime_error("PipeWire loop unavailable");
        std::unique_ptr<pw_context, decltype(&pw_context_destroy)> context(
            pw_context_new(pw_main_loop_get_loop(loop.get()), nullptr, 0), pw_context_destroy);
        if (!context) throw std::runtime_error("PipeWire client context unavailable");
        sockaddr_un address{}; address.sun_family = AF_UNIX;
        const auto length = std::strlen(argv[2]);
        if (!length || length >= sizeof(address.sun_path)) throw std::runtime_error("Invalid synthetic socket path");
        std::memcpy(address.sun_path, argv[2], length + 1);
        int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0) throw std::runtime_error("Synthetic socket unavailable");
        if (connect(fd, reinterpret_cast<sockaddr *>(&address), offsetof(sockaddr_un, sun_path) + length + 1)) {
            int failure = errno; close(fd); throw std::runtime_error(std::strerror(failure));
        }
        // The PipeWire API owns this FD on disconnect/error; no second reader.
        std::unique_ptr<pw_core, decltype(&pw_core_disconnect)> core(
            pw_context_connect_fd(context.get(), fd, nullptr, 0), pw_core_disconnect);
        if (!core) throw std::runtime_error("PipeWire protocol connection unavailable");
        Observation state{loop.get()}; spa_hook listener{};
        pw_core_add_listener(core.get(), &listener, &events, &state);
        auto *timer = pw_loop_add_timer(pw_main_loop_get_loop(loop.get()), +[](void *data, uint64_t) {
            auto &state = *static_cast<Observation *>(data);
            state.watchdog = true; pw_main_loop_quit(state.loop);
        }, &state);
        if (!timer) { spa_hook_remove(&listener); throw std::runtime_error("Probe watchdog unavailable"); }
        // Test-only observation watchdog, never a product connection deadline.
        timespec deadline{5, 0};
        int timer_result = pw_loop_update_timer(pw_main_loop_get_loop(loop.get()), timer, &deadline, nullptr, false);
        state.sequence = pw_core_sync(core.get(), PW_ID_CORE, 0);
        if (timer_result >= 0 && state.sequence >= 0) pw_main_loop_run(loop.get());
        pw_loop_destroy_source(pw_main_loop_get_loop(loop.get()), timer);
        spa_hook_remove(&listener);
        report["loadedProviders"] = loaded_providers();
        if (timer_result < 0 || state.sequence < 0 || state.error || state.watchdog || !state.completed)
            throw std::runtime_error(state.watchdog ? "Protocol probe watchdog expired" : "PipeWire protocol sync failed");
        report["connected"] = true;
        std::cout << report << '\n';
        return 0;
    } catch (const std::exception &error) {
        report["error"] = error.what();
        if (!report.contains("loadedProviders")) report["loadedProviders"] = loaded_providers();
        std::cout << report << '\n'; return 1;
    }
}
