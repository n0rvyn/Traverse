#include "portal_session.hpp"
#include "change_notification.hpp"
#include "input_keys.hpp"
#include <gio/gio.h>
#include <gio/gunixfdlist.h>
#include <glib-unix.h>
#include <algorithm>
#include <atomic>
#include <cstring>
#include <cmath>
#include <deque>
#include <fcntl.h>
#include <mutex>
#include <linux/input-event-codes.h>
#include <poll.h>
#include <set>
#include <stdexcept>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

namespace traverse {
namespace {
constexpr auto service = "org.freedesktop.portal.Desktop";
constexpr auto desktop = "/org/freedesktop/portal/desktop";
constexpr auto properties = "org.freedesktop.DBus.Properties";
constexpr auto remote = "org.freedesktop.portal.RemoteDesktop";
constexpr auto screen = "org.freedesktop.portal.ScreenCast";
constexpr auto session_interface = "org.freedesktop.portal.Session";
constexpr auto request_interface = "org.freedesktop.portal.Request";
struct PortalError : std::runtime_error {
    PortalSession::Failure kind;
    explicit PortalError(const GError *error) : std::runtime_error(error->message),
        kind(g_dbus_error_is_remote_error(error) ? PortalSession::Failure::Method : PortalSession::Failure::Transport) {}
};
using Variant = std::unique_ptr<GVariant, decltype(&g_variant_unref)>;
void unique_dictionary(GVariant *dictionary) {
    std::set<std::string> keys;
    GVariantIter iterator;
    g_variant_iter_init(&iterator, dictionary);
    const char *key = nullptr;
    GVariant *part = nullptr;
    while (g_variant_iter_next(&iterator, "{&sv}", &key, &part)) {
        Variant owned(part, g_variant_unref);
        if (!keys.insert(key).second) throw std::runtime_error("Duplicate portal field");
    }
}
std::string token() {
    char *uuid = g_uuid_string_random();
    std::string result = "traverse_" + std::string(uuid);
    g_free(uuid);
    std::replace(result.begin(), result.end(), '-', '_');
    return result;
}
std::uint32_t required_uint(GVariant *dictionary, const char *name) {
    guint32 value = 0;
    if (!g_variant_lookup(dictionary, name, "u", &value))
        throw std::runtime_error(std::string("Missing or invalid property: ") + name);
    return value;
}
int received_socket(GVariant *reply, GUnixFDList *list, GError **error) {
    if (*error) throw PortalError(*error);
    if (!reply || !g_variant_is_of_type(reply, G_VARIANT_TYPE("(h)")) || !list)
        throw std::runtime_error("Portal descriptor missing");
    gint32 index = -1; g_variant_get(reply, "(h)", &index);
    if (index < 0 || index >= g_unix_fd_list_get_length(list)) throw std::runtime_error("Invalid portal descriptor index");
    int fd = g_unix_fd_list_get(list, index, error);
    if (fd < 0) {
        if (*error) throw PortalError(*error);
        throw std::runtime_error("Portal descriptor unavailable");
    }
    int type = 0; socklen_t size = sizeof(type);
    sockaddr_storage address{}; socklen_t address_size = sizeof(address);
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &size) || type != SOCK_STREAM ||
        getsockname(fd, reinterpret_cast<sockaddr *>(&address), &address_size) || address.ss_family != AF_UNIX ||
        fcntl(fd, F_SETFD, FD_CLOEXEC)) {
        close(fd); throw std::runtime_error("Invalid portal descriptor transport");
    }
    return fd;
}
} // namespace

struct PortalSession::Impl {
    enum class Call { InitialOwner, Activate, Owner, RemoteProperties, ScreenProperties };
    struct Completion { Impl *owner; Call call; };
    mutable std::mutex mutex;
    std::mutex stop_mutex;
    Snapshot value;
    ChangeNotification changed;
    GMainContext *context = g_main_context_new();
    GMainLoop *loop = g_main_loop_new(context, FALSE);
    GCancellable *cancellation = g_cancellable_new();
    GDBusConnection *connection = nullptr;
    std::string owner;
    std::thread worker;
    unsigned pending = 0, owner_subscription = 0;
    bool shutting_down = false, connection_closing = false;
    std::atomic<bool> stop_requested{false};
    enum class Phase { Create, Devices, Sources, Start };
    struct PortalRequest {
        Impl *owner;
        Phase phase;
        std::string path;
        unsigned subscription = 0;
        bool returned = false, handled = false;
        Variant response{nullptr, g_variant_unref};
    };
    std::vector<std::shared_ptr<PortalRequest>> requests;
    std::optional<Request> requested;
    std::string session_path;
    unsigned session_subscription = 0;
    int pipewire_fd = -1, eis_fd = -1;
    int revocation_read = -1, revocation_write = -1;
    int consumer_read = -1;
    GSource *consumer_source = nullptr;
    struct RemoteRequest {
        Impl *owner;
        std::promise<Connection> result;
        bool completed = false; // protected by Impl::mutex
    };
    std::set<std::shared_ptr<RemoteRequest>> remote_requests;
    struct InputRequest {
        Input input;
        std::promise<void> result;
        bool completed = false; // protected by mutex
    };
    std::deque<std::shared_ptr<InputRequest>> input_requests; // includes in-flight head
    bool input_inflight = false; // worker only
    // Actual dispatched legacy edges, distinct from caller queue admission.
    // Retain uncertain in-flight presses until their corresponding release is
    // dispatched; queued presses cancelled by Stop never enter these sets.
    std::set<std::pair<Input::Kind,std::int32_t>> dispatched_keys;
    std::set<std::int32_t> dispatched_buttons;

    Failure validate_input_locked(const Input &input) const {
        if (stop_requested) return Failure::Cancelled;
        if (value.state != State::Granted || value.input_method != InputMethod::PortalDbus)
            return Failure::Unavailable;
        switch (input.kind) {
            case Input::Kind::PointerAbsolute: {
                if (!(value.granted_devices & 2u)) return Failure::Unavailable;
                auto stream = std::find_if(value.streams.begin(), value.streams.end(),
                    [&](const auto &candidate) { return candidate.node == input.stream; });
                if (stream == value.streams.end() || !stream->logical_size ||
                    !valid_pointer_position(input.x,input.y,stream->logical_size->first,stream->logical_size->second))
                    return Failure::InvalidInput;
                return Failure::None;
            }
            case Input::Kind::PointerButton:
                if (!(value.granted_devices & 2u)) return Failure::Unavailable;
                return valid_pointer_button(input.code) ? Failure::None : Failure::InvalidInput;
            case Input::Kind::PointerAxisDiscrete:
                if (!(value.granted_devices & 2u)) return Failure::Unavailable;
                return valid_discrete_axis(input.code,input.steps)
                    ? Failure::None : Failure::InvalidInput;
            case Input::Kind::KeyboardKeycode:
                if (!(value.granted_devices & 1u)) return Failure::Unavailable;
                // Kernel ABI validity, not an application key/count cap. The
                // authenticated DOM-key mapper remains the caller's boundary.
                return valid_keyboard_keycode(input.code)
                    ? Failure::None : Failure::InvalidInput;
            case Input::Kind::KeyboardKeysym: {
                if (!(value.granted_devices & 1u)) return Failure::Unavailable;
                static const auto symbols = key_symbols();
                return std::any_of(symbols.begin(), symbols.end(), [&](const auto &key) {
                    return key.second == static_cast<std::uint32_t>(input.code);
                }) ? Failure::None : Failure::InvalidInput;
            }
        }
        return Failure::InvalidInput;
    }
    void finish_input_locked(const std::shared_ptr<InputRequest> &request, Failure failure,
                             const std::string &message) {
        if (request->completed) return;
        request->completed = true;
        if (failure == Failure::None) request->result.set_value();
        else request->result.set_exception(std::make_exception_ptr(ConnectionError(failure, message)));
        changed.notify();
    }
    std::future<void> notify_input(const Input &input) {
        auto request = std::make_shared<InputRequest>(); request->input = input;
        auto future = request->result.get_future();
        {
            std::lock_guard lock(mutex);
            auto failure = validate_input_locked(input);
            if (failure != Failure::None) {
                finish_input_locked(request, failure, "Input unavailable or invalid for this desktop grant");
                return future;
            }
            input_requests.push_back(request);
            // Attach while holding the same lock as Stop, so a queued source
            // cannot be published after Stop has joined/destroyed the worker.
            GSource *source = g_idle_source_new();
            g_source_set_callback(source, [](gpointer data) -> gboolean {
                static_cast<Impl *>(data)->dispatch_input();
                return G_SOURCE_REMOVE;
            }, this, nullptr);
            g_source_attach(source, context); g_source_unref(source);
        }
        return future;
    }
    void dispatch_input() {
        // Only this worker dispatches. Keep the authority lock through call
        // submission, establishing a precise ordering against Stop's barrier.
        std::lock_guard lock(mutex);
        if (input_inflight || input_requests.empty() || shutting_down) return;
        const auto request = input_requests.front();
        auto failure = validate_input_locked(request->input);
        if (failure != Failure::None) {
            finish_input_locked(request, failure, "Desktop input authority ended");
            input_requests.pop_front();
            return;
        }
        const auto &input = request->input;
        GVariantBuilder options; g_variant_builder_init(&options, G_VARIANT_TYPE_VARDICT);
        const char *method = nullptr;
        GVariant *parameters = nullptr;
        switch (input.kind) {
            case Input::Kind::PointerAbsolute:
                method = "NotifyPointerMotionAbsolute";
                parameters = g_variant_new("(oa{sv}udd)", session_path.c_str(), &options,
                    input.stream, input.x, input.y); break;
            case Input::Kind::PointerButton:
                method = "NotifyPointerButton";
                parameters = g_variant_new("(oa{sv}iu)", session_path.c_str(), &options,
                    input.code, input.down ? 1u : 0u); break;
            case Input::Kind::PointerAxisDiscrete:
                method = "NotifyPointerAxisDiscrete";
                parameters = g_variant_new("(oa{sv}ui)", session_path.c_str(), &options,
                    static_cast<guint32>(input.code), input.steps); break;
            case Input::Kind::KeyboardKeycode:
                method = "NotifyKeyboardKeycode";
                parameters = g_variant_new("(oa{sv}iu)", session_path.c_str(), &options,
                    input.code, input.down ? 1u : 0u); break;
            case Input::Kind::KeyboardKeysym:
                method = "NotifyKeyboardKeysym";
                parameters = g_variant_new("(oa{sv}iu)", session_path.c_str(), &options,
                    input.code, input.down ? 1u : 0u); break;
        }
        struct Delivery { Impl *owner; std::shared_ptr<InputRequest> request; };
        auto *delivery = new Delivery{this, request};
        input_inflight = true;
        ++pending;
        g_dbus_connection_call(connection, owner.c_str(), desktop, remote, method, parameters,
            G_VARIANT_TYPE("()"), G_DBUS_CALL_FLAGS_NONE, G_MAXINT, cancellation,
            [](GObject *object, GAsyncResult *result, gpointer data) {
                std::unique_ptr<Delivery> delivery(static_cast<Delivery *>(data));
                auto *self = delivery->owner;
                GError *error = nullptr;
                Variant reply(g_dbus_connection_call_finish(G_DBUS_CONNECTION(object), result, &error), g_variant_unref);
                bool failed = false;
                Failure failure = error && g_dbus_error_is_remote_error(error) ? Failure::Method : Failure::Transport;
                std::string message = error ? error->message : "Invalid desktop input acknowledgment";
                {
                    std::lock_guard lock(self->mutex);
                    if (!delivery->request->completed) {
                        failed = error || !reply;
                        // An unacknowledged release is still an uncertain
                        // hold. Retire it only after a successful reply.
                        if (!failed && !delivery->request->input.down) {
                            const auto &input=delivery->request->input;
                            if (input.kind==Input::Kind::KeyboardKeycode || input.kind==Input::Kind::KeyboardKeysym)
                                self->dispatched_keys.erase(std::make_pair(input.kind,input.code));
                            else if (input.kind==Input::Kind::PointerButton) self->dispatched_buttons.erase(input.code);
                        }
                        self->finish_input_locked(delivery->request,
                            self->stop_requested ? Failure::Cancelled : failed ? failure : Failure::None,
                            self->stop_requested ? "Desktop input authority ended" : message);
                    }
                    if (!self->input_requests.empty() && self->input_requests.front() == delivery->request)
                        self->input_requests.pop_front();
                }
                self->input_inflight = false;
                if (failed && !self->shutting_down) self->fail(message, failure);
                g_clear_error(&error);
                --self->pending;
                if (!self->shutting_down) self->dispatch_input();
                self->maybe_quit();
            }, delivery);
        if (input.down && (input.kind==Input::Kind::KeyboardKeycode || input.kind==Input::Kind::KeyboardKeysym)) {
            auto key=std::make_pair(input.kind,input.code);
            dispatched_keys.insert(key);
        } else if (input.down && input.kind==Input::Kind::PointerButton) {
            dispatched_buttons.insert(input.code);
        }
    }


    Impl() {
        try {
            int descriptors[2];
            if (pipe2(descriptors, O_CLOEXEC | O_NONBLOCK)) throw std::runtime_error("Portal revocation channel unavailable");
            revocation_read = descriptors[0]; revocation_write = descriptors[1];
            worker = std::thread([this] { run(); });
        }
        catch (...) {
            if (revocation_read >= 0) close(revocation_read);
            if (revocation_write >= 0) close(revocation_write);
            g_object_unref(cancellation); g_main_loop_unref(loop); g_main_context_unref(context);
            throw;
        }
    }
    ~Impl() {
        stop();
        g_clear_object(&connection); g_object_unref(cancellation);
        g_main_loop_unref(loop); g_main_context_unref(context);
    }
    Snapshot snapshot() const { std::lock_guard lock(mutex); return value; }
    void revoke_connections_locked() {
        for (const auto &request : input_requests)
            finish_input_locked(request, Failure::Cancelled, "Desktop input authority ended");
        input_requests.clear();
        if (revocation_write >= 0) { close(revocation_write); revocation_write = -1; }
        if (revocation_read >= 0) { close(revocation_read); revocation_read = -1; }
        for (auto &request : remote_requests) {
            if (!request->completed) {
                request->completed = true;
                request->result.set_exception(std::make_exception_ptr(ConnectionError(Failure::Cancelled, "Portal session ended")));
                changed.notify();
            }
        }
        remote_requests.clear();
    }
    std::future<Connection> open_pipewire_connection() {
        auto request = std::make_shared<RemoteRequest>(); request->owner = this;
        auto future = request->result.get_future();
        {
            std::lock_guard lock(mutex);
            if (stop_requested || value.state != State::Granted) {
                request->result.set_exception(std::make_exception_ptr(ConnectionError(
                    stop_requested ? Failure::Cancelled : Failure::Unavailable, "Desktop session not granted")));
                changed.notify();
                return future;
            }
            remote_requests.insert(request);
        }
        GSource *source = g_idle_source_new();
        g_source_set_callback(source, [](gpointer data) -> gboolean {
            auto request = *static_cast<std::shared_ptr<RemoteRequest> *>(data);
            try { request->owner->begin_remote(request); }
            catch (const std::exception &error) {
                request->owner->finish_remote(request, -1, Failure::Transport, error.what());
            }
            return G_SOURCE_REMOVE;
        }, new std::shared_ptr<RemoteRequest>(request),
        [](gpointer data) { delete static_cast<std::shared_ptr<RemoteRequest> *>(data); });
        g_source_attach(source, context); g_source_unref(source);
        return future;
    }
    void finish_remote(const std::shared_ptr<RemoteRequest> &request, int fd, Failure failure, const std::string &error) {
        std::lock_guard lock(mutex);
        if (request->completed) { if (fd >= 0) close(fd); return; }
        if (stop_requested || value.state != State::Granted) {
            failure = Failure::Cancelled;
        }
        int notification = -1;
        if (fd >= 0 && failure == Failure::None) {
            notification = fcntl(revocation_read, F_DUPFD_CLOEXEC, 0);
            if (notification < 0) failure = Failure::Transport;
        }
        request->completed = true;
        remote_requests.erase(request);
        if (failure != Failure::None || fd < 0) {
            if (fd >= 0) close(fd);
            request->result.set_exception(std::make_exception_ptr(ConnectionError(failure,
                failure == Failure::Cancelled ? "Portal session ended" : error.empty() ? "Capture connection unavailable" : error)));
        } else request->result.set_value(Connection(fd, notification, Connection::Protocol::PipeWire));
        changed.notify();
    }
    void begin_remote(const std::shared_ptr<RemoteRequest> &request) {
        int initial = -1;
        {
            std::lock_guard lock(mutex);
            if (request->completed) return;
            if (pipewire_fd >= 0) { initial = pipewire_fd; pipewire_fd = -1; }
        }
        if (initial >= 0) { finish_remote(request, initial, Failure::None, {}); return; }
        if (shutting_down || stop_requested) { finish_remote(request, -1, Failure::Cancelled, {}); return; }
        GVariantBuilder options; g_variant_builder_init(&options, G_VARIANT_TYPE_VARDICT);
        auto *holder = new std::shared_ptr<RemoteRequest>(request);
        ++pending;
        g_dbus_connection_call_with_unix_fd_list(connection, owner.c_str(), desktop, screen,
            "OpenPipeWireRemote", g_variant_new("(oa{sv})", session_path.c_str(), &options), G_VARIANT_TYPE("(h)"),
            G_DBUS_CALL_FLAGS_NONE, G_MAXINT, nullptr, cancellation,
            [](GObject *object, GAsyncResult *result, gpointer data) {
                std::unique_ptr<std::shared_ptr<RemoteRequest>> holder(static_cast<std::shared_ptr<RemoteRequest> *>(data));
                auto request = *holder; auto *self = request->owner;
                GError *error = nullptr; GUnixFDList *list = nullptr;
                Variant reply(g_dbus_connection_call_with_unix_fd_list_finish(G_DBUS_CONNECTION(object), &list, result, &error), g_variant_unref);
                int fd = -1;
                try {
                    if (self->shutting_down || self->stop_requested) self->finish_remote(request, -1, Failure::Cancelled, {});
                    else {
                        fd = received_socket(reply.get(), list, &error);
                        int transferred = fd; fd = -1;
                        self->finish_remote(request, transferred, Failure::None, {});
                    }
                } catch (const std::exception &failure) {
                    if (fd >= 0) close(fd);
                    const auto *portal = dynamic_cast<const PortalError *>(&failure);
                    self->finish_remote(request, -1, portal ? portal->kind : Failure::InvalidResponse, failure.what());
                }
                g_clear_error(&error); g_clear_object(&list);
                --self->pending; self->maybe_quit();
            }, holder);
    }
    Connection take_eis_connection() {
        std::lock_guard lock(mutex);
        if (stop_requested || value.state != State::Granted ||
            value.input_method != InputMethod::Eis || eis_fd < 0)
            throw ConnectionError(stop_requested ? Failure::Cancelled : Failure::Unavailable,
                                  "EIS connection unavailable");
        int lifetime[2];
        if (pipe2(lifetime, O_CLOEXEC | O_NONBLOCK))
            throw ConnectionError(Failure::Transport, "EIS consumer lifetime channel unavailable");
        int notification = fcntl(revocation_read, F_DUPFD_CLOEXEC, 0);
        if (notification < 0) {
            close(lifetime[0]); close(lifetime[1]);
            throw ConnectionError(Failure::Transport, "EIS revocation channel unavailable");
        }
        GSource *source = g_unix_fd_source_new(lifetime[0], GIOCondition(G_IO_HUP | G_IO_ERR | G_IO_NVAL));
        g_source_set_callback(source, G_SOURCE_FUNC(+[](gint, GIOCondition, gpointer data) -> gboolean {
            auto *self = static_cast<Impl *>(data);
            {
                std::lock_guard lock(self->mutex);
                self->stop_requested = true;
                self->value.state = State::Stopped;
                self->value.failure = Failure::None;
                self->value.error.clear();
                self->value.operation = "EIS consumer ended";
                self->changed.notify();
            }
            self->shutdown();
            return G_SOURCE_REMOVE;
        }), this, nullptr);
        if (!g_source_attach(source, context)) {
            g_source_unref(source); close(notification); close(lifetime[0]); close(lifetime[1]);
            throw ConnectionError(Failure::Transport, "EIS consumer lifetime observation unavailable");
        }
        consumer_source = source;
        consumer_read = lifetime[0];
        return Connection(std::exchange(eis_fd, -1), notification, Connection::Protocol::Eis, lifetime[1]);
    }
    int take_fd(bool eis) {
        std::lock_guard lock(mutex);
        int &fd = eis ? eis_fd : pipewire_fd;
        if (stop_requested || value.state != State::Granted || fd < 0)
            throw std::runtime_error("Portal descriptor not available");
        const int result = fd;
        fd = -1;
        return result;
    }
    bool request(const Request &selection) {
        if (!g_utf8_validate(selection.parent_window.data(), selection.parent_window.size(), nullptr)) return false;
        auto task = std::make_unique<std::pair<Impl *, Request>>(this, selection);
        {
            std::lock_guard lock(mutex);
            if (stop_requested || value.state != State::CapabilitiesReady || !selection.devices ||
                (selection.devices & ~7u) || (selection.devices & value.devices) != selection.devices ||
                !selection.source_types || (selection.source_types & ~7u) ||
                (selection.source_types & value.sources) != selection.source_types ||
                !(selection.cursor_mode == 1 || selection.cursor_mode == 2 || selection.cursor_mode == 4)) return false;
            if (value.cursor_modes ? (selection.cursor_mode & *value.cursor_modes) != selection.cursor_mode : selection.cursor_mode != 1)
                return false;
            value.state = State::Requesting;
            changed.notify();
        }
        GSource *source = g_idle_source_new();
        g_source_set_callback(source, [](gpointer data) -> gboolean {
            auto &task = *static_cast<std::pair<Impl *, Request> *>(data);
            if (!task.first->shutting_down) {
                try { task.first->begin_request(task.second); }
                catch (const std::exception &error) { task.first->fail_exception(error); }
            }
            return G_SOURCE_REMOVE;
        }, task.release(), [](gpointer data) { delete static_cast<std::pair<Impl *, Request> *>(data); });
        g_source_attach(source, context); g_source_unref(source);
        return true;
    }
    void operation(const char *name) { std::lock_guard lock(mutex); value.operation = name; changed.notify(); }
    void fail_exception(const std::exception &error) {
        const auto *portal = dynamic_cast<const PortalError *>(&error);
        fail(error.what(), portal ? portal->kind : Failure::InvalidResponse);
    }
    void fail(const std::string &message, Failure failure = Failure::InvalidResponse, bool cleanup_owned = true) {
        if (!shutting_down) {
            bool permitted_release=false;
            { std::lock_guard lock(mutex);
              permitted_release=cleanup_owned && value.state==State::Granted && value.input_method==InputMethod::PortalDbus;
              value.state = stop_requested ? State::Stopped : State::Failed;
              value.error = stop_requested ? std::string{} : message;
              value.failure = stop_requested ? Failure::None : failure; changed.notify(); }
            shutdown(permitted_release);
        }
    }
    void maybe_quit() {
        if (shutting_down && !pending && !connection_closing) g_main_loop_quit(loop);
    }
    void close_connection() {
        if (!connection || connection_closing) return;
        if (owner_subscription) {
            g_dbus_connection_signal_unsubscribe(connection, owner_subscription);
            owner_subscription = 0;
        }
        if (session_subscription) {
            g_dbus_connection_signal_unsubscribe(connection, session_subscription);
            session_subscription = 0;
        }
        for (auto &request : requests) {
            if (request->subscription) g_dbus_connection_signal_unsubscribe(connection, request->subscription);
            request->subscription = 0;
        }
        requests.clear();
        connection_closing = true;
        g_dbus_connection_close(connection, nullptr, [](GObject *object, GAsyncResult *result, gpointer data) {
            auto *self = static_cast<Impl *>(data);
            GError *error = nullptr;
            g_dbus_connection_close_finish(G_DBUS_CONNECTION(object), result, &error);
            g_clear_error(&error);
            self->connection_closing = false;
            self->maybe_quit();
        }, this);
    }
    void cleanup_error(const std::string &message) {
        std::lock_guard lock(mutex);
        if (value.error.empty()) {value.error=message;value.failure=Failure::Transport;changed.notify();}
    }
    void release_dispatched_then_close() {
        if (dispatched_keys.empty() && dispatched_buttons.empty()) {close_connection();return;}
        // Shutdown must not wait for a stalled input-method reply. Send only
        // terminal owned releases, then flush them to the private bus before
        // owner loss revokes the grant. This is a shutdown transport barrier,
        // never a successful acknowledgment for ordinary notify_input().
        auto send_release=[&](const char *method,std::int32_t code) {
            if (!connection || g_dbus_connection_is_closed(connection) || owner.empty() || session_path.empty()) {
                cleanup_error("Owned desktop input releases could not be sent");return;
            }
            GVariantBuilder options;g_variant_builder_init(&options,G_VARIANT_TYPE_VARDICT);
            auto *message=g_dbus_message_new_method_call(owner.c_str(),desktop,remote,method);
            g_dbus_message_set_flags(message,G_DBUS_MESSAGE_FLAGS_NO_REPLY_EXPECTED);
            g_dbus_message_set_body(message,g_variant_new("(oa{sv}iu)",session_path.c_str(),&options,code,0u));
            GError *error=nullptr;
            if (!g_dbus_connection_send_message(connection,message,G_DBUS_SEND_MESSAGE_FLAGS_NONE,nullptr,&error))
                cleanup_error(error ? error->message : "Owned desktop input release transport failed");
            g_clear_error(&error);g_object_unref(message);
        };
        for (const auto &key:dispatched_keys)
            send_release(key.first==Input::Kind::KeyboardKeycode ? "NotifyKeyboardKeycode" : "NotifyKeyboardKeysym",key.second);
        for (auto button:dispatched_buttons) send_release("NotifyPointerButton",button);
        dispatched_keys.clear();dispatched_buttons.clear();
        if (!connection || g_dbus_connection_is_closed(connection)) {close_connection();return;}
        ++pending;
        g_dbus_connection_flush(connection,nullptr,[](GObject *object,GAsyncResult *result,gpointer data) {
            auto *self=static_cast<Impl *>(data);GError *error=nullptr;
            if (!g_dbus_connection_flush_finish(G_DBUS_CONNECTION(object),result,&error))
                self->cleanup_error(error ? error->message : "Owned input cleanup flush failed");
            g_clear_error(&error);--self->pending;
            self->close_connection();self->maybe_quit();
        },this);
    }
    void shutdown(bool cleanup_owned = false) {
        if (shutting_down) return;
        shutting_down = true;
        {
            std::lock_guard lock(mutex);
            if (consumer_source) {
                g_source_destroy(consumer_source); g_source_unref(consumer_source);
                consumer_source = nullptr;
            }
            if (consumer_read >= 0) { close(consumer_read); consumer_read = -1; }
            revoke_connections_locked();
            if (pipewire_fd >= 0) { close(pipewire_fd); pipewire_fd = -1; }
            if (eis_fd >= 0) { close(eis_fd); eis_fd = -1; }
        }
        // Losing this private bus owner closes every session it created. This
        // also revokes a session whose Create reply arrives after cancellation.
        g_cancellable_cancel(cancellation);
        if (cleanup_owned) release_dispatched_then_close();
        else {dispatched_keys.clear();dispatched_buttons.clear();close_connection();}
        maybe_quit();
    }
    void stop() {
        // Only this method joins; no callback into a caller or self-join path.
        std::lock_guard stop_lock(stop_mutex);
        { std::lock_guard lock(mutex); stop_requested = true; revoke_connections_locked(); }
        if (!worker.joinable()) return;
        GSource *source = g_idle_source_new();
        g_source_set_priority(source, G_PRIORITY_HIGH);
        g_source_set_callback(source, [](gpointer data) -> gboolean {
            auto *self = static_cast<Impl *>(data);
            if (!self->shutting_down) {
                bool cleanup_owned=false;
                { std::lock_guard lock(self->mutex);
                  cleanup_owned=self->value.state==State::Granted && self->value.input_method==InputMethod::PortalDbus;
                  self->value.state = State::Stopped; self->changed.notify(); }
                self->shutdown(cleanup_owned);
            }
            return G_SOURCE_REMOVE;
        }, this, nullptr);
        g_source_attach(source, context); g_source_unref(source);
        worker.join();
    }
    void call(Call kind, const char *destination, const char *path, const char *interface,
              const char *method, GVariant *parameters, const GVariantType *reply) {
        operation(method);
        auto *completion = new Completion{this, kind};
        ++pending;
        // No permission wait uses this probe. Explicit cancellation also governs
        // a hung properties/activation call; do not inherit a hidden 25s timeout.
        g_dbus_connection_call(connection, destination, path, interface, method, parameters, reply,
                               G_DBUS_CALL_FLAGS_NONE, G_MAXINT, cancellation,
            [](GObject *object, GAsyncResult *result, gpointer data) {
                std::unique_ptr<Completion> completed(static_cast<Completion *>(data));
                auto *self = completed->owner;
                GError *error = nullptr;
                Variant response(g_dbus_connection_call_finish(G_DBUS_CONNECTION(object), result, &error), g_variant_unref);
                if (!self->shutting_down) {
                    try {
                        if (error && completed->call == Call::InitialOwner &&
                            g_error_matches(error, G_DBUS_ERROR, G_DBUS_ERROR_NAME_HAS_NO_OWNER)) {
                            self->call(Call::Activate, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "StartServiceByName", g_variant_new("(su)", service, 0u), G_VARIANT_TYPE("(u)"));
                        } else {
                            if (error) throw PortalError(error);
                            if (!response) throw std::runtime_error("Portal method returned no result");
                            self->returned(completed->call, response.get());
                        }
                    } catch (const std::exception &failure) { self->fail_exception(failure); }
                }
                g_clear_error(&error);
                --self->pending;
                self->maybe_quit();
            }, completion);
    }
    void begin_request(const Request &selection) {
        requested = selection;
        const char *name = g_dbus_connection_get_unique_name(connection);
        if (!name || !g_dbus_is_unique_name(name)) throw std::runtime_error("Private portal owner unavailable");
        std::string sender(name + 1);
        std::replace(sender.begin(), sender.end(), '.', '_');
        session_path = "/org/freedesktop/portal/desktop/session/" + sender + "/" + token();
        session_subscription = g_dbus_connection_signal_subscribe(connection, owner.c_str(), session_interface,
            "Closed", session_path.c_str(), nullptr, G_DBUS_SIGNAL_FLAGS_NONE,
            [](GDBusConnection *, const gchar *, const gchar *, const gchar *, const gchar *, GVariant *parameters, gpointer data) {
                auto *self = static_cast<Impl *>(data);
                if (self->shutting_down) return;
                if (!g_variant_is_of_type(parameters, G_VARIANT_TYPE("(a{sv})"))) {
                    self->fail("Invalid session closure observation"); return;
                }
                { std::lock_guard lock(self->mutex); self->value.state = State::Closed; self->changed.notify(); }
                self->shutdown();
            }, this, nullptr);
        send_request(Phase::Create);
    }
    void send_request(Phase phase) {
        auto request = std::make_shared<PortalRequest>();
        request->owner = this; request->phase = phase;
        auto handle = token();
        std::string sender(g_dbus_connection_get_unique_name(connection) + 1);
        std::replace(sender.begin(), sender.end(), '.', '_');
        request->path = "/org/freedesktop/portal/desktop/request/" + sender + "/" + handle;
        request->subscription = g_dbus_connection_signal_subscribe(connection, owner.c_str(), request_interface,
            "Response", request->path.c_str(), nullptr, G_DBUS_SIGNAL_FLAGS_NONE,
            [](GDBusConnection *, const gchar *sender, const gchar *path, const gchar *, const gchar *, GVariant *parameters, gpointer data) {
                auto request = *static_cast<std::shared_ptr<PortalRequest> *>(data);
                auto *self = request->owner;
                if (self->shutting_down || request->handled) return;
                try {
                    if (!sender || self->owner != sender || !path || request->path != path ||
                        !g_variant_is_of_type(parameters, G_VARIANT_TYPE("(ua{sv})")))
                        throw std::runtime_error("Invalid portal response identity or signature");
                    if (request->response) throw std::runtime_error("Duplicate portal response");
                    request->response.reset(g_variant_ref(parameters));
                    self->process_request(request);
                } catch (const std::exception &error) { self->fail_exception(error); }
            }, new std::shared_ptr<PortalRequest>(request),
            [](gpointer data) { delete static_cast<std::shared_ptr<PortalRequest> *>(data); });
        requests.push_back(request);
        GVariantBuilder options;
        g_variant_builder_init(&options, G_VARIANT_TYPE_VARDICT);
        g_variant_builder_add(&options, "{sv}", "handle_token", g_variant_new_string(handle.c_str()));
        const char *method = nullptr, *interface = remote;
        GVariant *parameters = nullptr;
        if (phase == Phase::Create) {
            auto session_token = session_path.substr(session_path.find_last_of('/') + 1);
            g_variant_builder_add(&options, "{sv}", "session_handle_token", g_variant_new_string(session_token.c_str()));
            method = "CreateSession"; parameters = g_variant_new("(a{sv})", &options);
        } else if (phase == Phase::Devices) {
            g_variant_builder_add(&options, "{sv}", "types", g_variant_new_uint32(requested->devices));
            method = "SelectDevices"; parameters = g_variant_new("(oa{sv})", session_path.c_str(), &options);
        } else if (phase == Phase::Sources) {
            g_variant_builder_add(&options, "{sv}", "types", g_variant_new_uint32(requested->source_types));
            g_variant_builder_add(&options, "{sv}", "multiple", g_variant_new_boolean(requested->multiple));
            if (snapshot().screen_version >= 2)
                g_variant_builder_add(&options, "{sv}", "cursor_mode", g_variant_new_uint32(requested->cursor_mode));
            interface = screen; method = "SelectSources";
            parameters = g_variant_new("(oa{sv})", session_path.c_str(), &options);
        } else {
            method = "Start";
            parameters = g_variant_new("(osa{sv})", session_path.c_str(), requested->parent_window.c_str(), &options);
        }
        operation(method);
        ++pending;
        g_dbus_connection_call(connection, owner.c_str(), desktop, interface, method, parameters,
            G_VARIANT_TYPE("(o)"), G_DBUS_CALL_FLAGS_NONE, G_MAXINT, cancellation,
            [](GObject *object, GAsyncResult *result, gpointer data) {
                std::unique_ptr<std::shared_ptr<PortalRequest>> holder(static_cast<std::shared_ptr<PortalRequest> *>(data));
                auto request = *holder; auto *self = request->owner;
                GError *error = nullptr;
                Variant reply(g_dbus_connection_call_finish(G_DBUS_CONNECTION(object), result, &error), g_variant_unref);
                if (!self->shutting_down) {
                    try {
                        if (error) throw PortalError(error);
                        if (!reply) throw std::runtime_error("Portal request returned no handle");
                        const char *path = nullptr; g_variant_get(reply.get(), "(&o)", &path);
                        if (!path || request->path != path) throw std::runtime_error("Unexpected portal request handle");
                        request->returned = true;
                        if (request->phase == Phase::Start && !request->response) {
                            std::lock_guard lock(self->mutex); self->value.state = State::WaitingPermission; self->changed.notify();
                        }
                        self->process_request(request);
                    } catch (const std::exception &failure) { self->fail_exception(failure); }
                }
                g_clear_error(&error); --self->pending; self->maybe_quit();
            }, new std::shared_ptr<PortalRequest>(request));
    }
    void process_request(const std::shared_ptr<PortalRequest> &request) {
        if (!request->returned || !request->response || request->handled || shutting_down) return;
        if (stop_requested) {
            { std::lock_guard lock(mutex); value.state = State::Stopped; changed.notify(); }
            shutdown(); return;
        }
        request->handled = true;
        if (request->subscription) g_dbus_connection_signal_unsubscribe(connection, request->subscription);
        request->subscription = 0;
        requests.erase(std::remove(requests.begin(), requests.end(), request), requests.end());
        Variant code(g_variant_get_child_value(request->response.get(), 0), g_variant_unref);
        Variant results(g_variant_get_child_value(request->response.get(), 1), g_variant_unref);
        const auto response = g_variant_get_uint32(code.get());
        unique_dictionary(results.get());
        if (response) {
            if (response > 2) throw std::runtime_error("Invalid portal response code");
            { std::lock_guard lock(mutex); value.state = State::NotGranted; value.portal_response = response;
              value.error = response == 1 ? "Portal request cancelled" : "Portal request failed"; changed.notify(); }
            shutdown(); return;
        }
        if (request->phase == Phase::Create) {
            // The portal ABI deliberately retains string type for this path.
            const char *path = nullptr;
            if (!g_variant_lookup(results.get(), "session_handle", "&s", &path) || !path ||
                !g_variant_is_object_path(path) || session_path != path)
                throw std::runtime_error("Invalid portal session handle");
            send_request(Phase::Devices);
        } else if (request->phase == Phase::Devices) send_request(Phase::Sources);
        else if (request->phase == Phase::Sources) send_request(Phase::Start);
        else {
            const auto devices = required_uint(results.get(), "devices");
            if ((devices & requested->devices) != requested->devices) {
                { std::lock_guard lock(mutex); value.state = State::NotGranted;
                  value.granted_devices = devices & requested->devices;
                  value.error = "Required desktop input permission not granted"; changed.notify(); }
                shutdown(); return;
            }
            auto streams = read_streams(results.get());
            { std::lock_guard lock(mutex); value.state = State::Requesting;
              value.granted_devices = devices & requested->devices; value.streams = std::move(streams); changed.notify(); }
            open_fd(false);
        }
    }
    std::vector<Stream> read_streams(GVariant *results) {
        Variant streams(g_variant_lookup_value(results, "streams", G_VARIANT_TYPE("a(ua{sv})")), g_variant_unref);
        if (!streams || !g_variant_n_children(streams.get()) ||
            (!requested->multiple && g_variant_n_children(streams.get()) != 1))
            throw std::runtime_error("Invalid granted screen streams");
        std::vector<Stream> result;
        std::set<std::uint32_t> nodes;
        for (gsize i = 0; i < g_variant_n_children(streams.get()); ++i) {
            if (stop_requested) throw std::runtime_error("Portal operation cancelled");
            Variant tuple(g_variant_get_child_value(streams.get(), i), g_variant_unref);
            Variant node(g_variant_get_child_value(tuple.get(), 0), g_variant_unref);
            Variant properties(g_variant_get_child_value(tuple.get(), 1), g_variant_unref);
            unique_dictionary(properties.get());
            Stream stream{}; stream.node = g_variant_get_uint32(node.get());
            if (!nodes.insert(stream.node).second) throw std::runtime_error("Ambiguous granted screen identity");
            auto optional = [&](const char *key, const GVariantType *type) {
                Variant part(g_variant_lookup_value(properties.get(), key, nullptr), g_variant_unref);
                if (part && !g_variant_is_of_type(part.get(), type)) throw std::runtime_error("Invalid stream property type");
                return part;
            };
            auto serial = optional("pipewire-serial", G_VARIANT_TYPE_UINT64);
            if (serial) stream.serial = g_variant_get_uint64(serial.get());
            auto source_type = optional("source_type", G_VARIANT_TYPE_UINT32);
            if (source_type) {
                auto type = g_variant_get_uint32(source_type.get());
                if (!(type == 1 || type == 2 || type == 4) || !(type & requested->source_types))
                    throw std::runtime_error("Unexpected granted screen source type");
                stream.source_type = type;
            }
            for (const char *key : {"position", "size"}) {
                auto part = optional(key, G_VARIANT_TYPE("(ii)"));
                if (!part) continue;
                gint32 x = 0, y = 0; g_variant_get(part.get(), "(ii)", &x, &y);
                if (!strcmp(key, "size")) {
                    if (x <= 0 || y <= 0) throw std::runtime_error("Invalid logical stream size");
                    stream.logical_size = std::make_pair(x, y);
                } else stream.position = std::make_pair(x, y);
            }
            auto mapping = optional("mapping_id", G_VARIANT_TYPE_STRING);
            if (mapping) stream.mapping_id = g_variant_get_string(mapping.get(), nullptr);
            result.push_back(std::move(stream));
        }
        return result;
    }
    void open_fd(bool eis) {
        operation(eis ? "ConnectToEIS" : "OpenPipeWireRemote");
        GVariantBuilder options; g_variant_builder_init(&options, G_VARIANT_TYPE_VARDICT);
        ++pending;
        auto *completion = new std::pair<Impl *, bool>(this, eis);
        g_dbus_connection_call_with_unix_fd_list(connection, owner.c_str(), desktop, eis ? remote : screen,
            eis ? "ConnectToEIS" : "OpenPipeWireRemote", g_variant_new("(oa{sv})", session_path.c_str(), &options),
            G_VARIANT_TYPE("(h)"), G_DBUS_CALL_FLAGS_NONE, G_MAXINT, nullptr, cancellation,
            [](GObject *object, GAsyncResult *result, gpointer data) {
                std::unique_ptr<std::pair<Impl *, bool>> completion(static_cast<std::pair<Impl *, bool> *>(data));
                auto *self = completion->first; const bool eis = completion->second;
                GError *error = nullptr; GUnixFDList *list = nullptr;
                Variant reply(g_dbus_connection_call_with_unix_fd_list_finish(G_DBUS_CONNECTION(object), &list, result, &error), g_variant_unref);
                if (!self->shutting_down && self->stop_requested) self->fail("Portal operation cancelled");
                if (!self->shutting_down) {
                    int fd = -1;
                    try {
                        char *remote_error = error ? g_dbus_error_get_remote_error(error) : nullptr;
                        bool unsupported = remote_error && (!strcmp(remote_error, "org.freedesktop.DBus.Error.UnknownMethod") ||
                            !strcmp(remote_error, "org.freedesktop.DBus.Error.NotSupported") ||
                            !strcmp(remote_error, "org.freedesktop.portal.Error.NotSupported"));
                        g_free(remote_error);
                        if (eis && unsupported && !reply && (!list || !g_unix_fd_list_get_length(list))) {
                            std::lock_guard lock(self->mutex);
                            self->value.input_method = InputMethod::PortalDbus; self->value.state = State::Granted; self->value.operation.clear(); self->changed.notify();
                        } else {
                            fd = received_socket(reply.get(), list, &error);
                            {
                                std::lock_guard lock(self->mutex);
                                if (eis) { self->eis_fd = fd; self->value.input_method = InputMethod::Eis; }
                                else self->pipewire_fd = fd;
                                fd = -1;
                                if (eis || self->value.remote_version < 2) {
                                    if (!eis) self->value.input_method = InputMethod::PortalDbus;
                                    self->value.state = State::Granted; self->value.operation.clear(); self->changed.notify();
                                }
                            }
                            if (!eis && self->snapshot().remote_version >= 2) self->open_fd(true);
                        }
                    } catch (const std::exception &failure) { if (fd >= 0) close(fd); self->fail_exception(failure); }
                }
                g_clear_error(&error); g_clear_object(&list);
                --self->pending; self->maybe_quit();
            }, completion);
    }
    void returned(Call kind, GVariant *reply) {
        if (kind == Call::Activate) {
            guint32 result = 0; g_variant_get(reply, "(u)", &result);
            if (result != 1 && result != 2) throw std::runtime_error("Portal activation failed");
            call(Call::Owner, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                 "GetNameOwner", g_variant_new("(s)", service), G_VARIANT_TYPE("(s)"));
        } else if (kind == Call::Owner || kind == Call::InitialOwner) {
            const char *name = nullptr; g_variant_get(reply, "(&s)", &name);
            if (!name || !g_dbus_is_unique_name(name)) throw std::runtime_error("Portal unique owner unavailable");
            owner = name;
            call(Call::RemoteProperties, owner.c_str(), desktop, properties, "GetAll",
                 g_variant_new("(s)", remote), G_VARIANT_TYPE("(a{sv})"));
        } else {
            Variant dictionary(g_variant_get_child_value(reply, 0), g_variant_unref);
            unique_dictionary(dictionary.get());
            if (kind == Call::RemoteProperties) {
                auto version = required_uint(dictionary.get(), "version");
                auto devices = required_uint(dictionary.get(), "AvailableDeviceTypes");
                if (!version) throw std::runtime_error("Invalid remote desktop version");
                { std::lock_guard lock(mutex); value.remote_version = version; value.devices = devices; changed.notify(); }
                call(Call::ScreenProperties, owner.c_str(), desktop, properties, "GetAll",
                     g_variant_new("(s)", screen), G_VARIANT_TYPE("(a{sv})"));
            } else {
                auto version = required_uint(dictionary.get(), "version");
                auto sources = required_uint(dictionary.get(), "AvailableSourceTypes");
                if (!version) throw std::runtime_error("Invalid screen cast version");
                auto cursors = version >= 2 ? std::optional<std::uint32_t>(required_uint(dictionary.get(), "AvailableCursorModes")) : std::nullopt;
                std::lock_guard lock(mutex);
                value.screen_version = version; value.sources = sources; value.cursor_modes = cursors;
                value.state = State::CapabilitiesReady; value.operation.clear(); changed.notify();
            }
        }
    }
    void run() {
        g_main_context_push_thread_default(context);
        const char *address = g_getenv("DBUS_SESSION_BUS_ADDRESS");
        if (!address || !*address) {
            std::lock_guard lock(mutex); value.state = State::Failed; value.error = "Session bus address unavailable"; value.failure = Failure::Unavailable; changed.notify();
        } else {
            ++pending;
            g_dbus_connection_new_for_address(address,
                GDBusConnectionFlags(G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT | G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION),
                nullptr, cancellation, [](GObject *, GAsyncResult *result, gpointer data) {
                    auto *self = static_cast<Impl *>(data);
                    GError *error = nullptr;
                    self->connection = g_dbus_connection_new_for_address_finish(result, &error);
                    if (self->connection) {
                        g_dbus_connection_set_exit_on_close(self->connection, FALSE);
                        self->owner_subscription = g_dbus_connection_signal_subscribe(self->connection, "org.freedesktop.DBus",
                            "org.freedesktop.DBus", "NameOwnerChanged", "/org/freedesktop/DBus", service,
                            G_DBUS_SIGNAL_FLAGS_NONE,
                            [](GDBusConnection *, const gchar *, const gchar *, const gchar *, const gchar *, GVariant *parameters, gpointer data) {
                                auto *self = static_cast<Impl *>(data);
                                const char *name = nullptr, *old_owner = nullptr, *new_owner = nullptr;
                                if (!g_variant_is_of_type(parameters, G_VARIANT_TYPE("(sss)"))) { self->fail("Invalid portal owner observation"); return; }
                                g_variant_get(parameters, "(&s&s&s)", &name, &old_owner, &new_owner);
                                (void)name; (void)old_owner;
                                if (!self->owner.empty() && self->owner != new_owner) self->fail("Portal owner changed", Failure::Transport, false);
                            }, self, nullptr);
                        g_signal_connect(self->connection, "closed", G_CALLBACK(+[](GDBusConnection *, gboolean, GError *, gpointer data) {
                            auto *self = static_cast<Impl *>(data);
                            self->fail("Session bus connection closed", Failure::Transport);
                        }), self);
                    }
                    if (self->shutting_down) self->close_connection();
                    else if (error || !self->connection) self->fail(error ? error->message : "Session bus unavailable", Failure::Transport);
                    else self->call(Call::InitialOwner, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                    "GetNameOwner", g_variant_new("(s)", service), G_VARIANT_TYPE("(s)"));
                    g_clear_error(&error);
                    --self->pending; self->maybe_quit();
                }, this);
            g_main_loop_run(loop);
        }
        g_main_context_pop_thread_default(context);
    }
};

PortalSession::Connection::~Connection() {
    if (fd >= 0) close(fd);
    if (revoked >= 0) close(revoked);
    if (consumer >= 0) close(consumer);
}
PortalSession::Connection::Connection(Connection &&other) noexcept
    : fd(std::exchange(other.fd, -1)), revoked(std::exchange(other.revoked, -1)),
      consumer(std::exchange(other.consumer, -1)), kind(std::exchange(other.kind, Protocol::None)) {}
PortalSession::Connection &PortalSession::Connection::operator=(Connection &&other) noexcept {
    if (this != &other) {
        if (fd >= 0) close(fd);
        if (revoked >= 0) close(revoked);
        if (consumer >= 0) close(consumer);
        fd = std::exchange(other.fd, -1); revoked = std::exchange(other.revoked, -1);
        consumer = std::exchange(other.consumer, -1); kind = std::exchange(other.kind, Protocol::None);
    }
    return *this;
}
bool PortalSession::Connection::valid() const noexcept {
    if (fd < 0 || revoked < 0) return false;
    pollfd notification{revoked, POLLIN | POLLHUP, 0};
    return poll(&notification, 1, 0) == 0;
}
PortalSession::PortalSession() : impl(std::make_unique<Impl>()) {}
PortalSession::~PortalSession() = default;
PortalSession::Snapshot PortalSession::snapshot() const { return impl->snapshot(); }
int PortalSession::state_descriptor() const noexcept { return impl->changed.descriptor(); }
bool PortalSession::request(const Request &request) { return impl->request(request); }
int PortalSession::take_pipewire_fd() { return impl->take_fd(false); }
int PortalSession::take_eis_fd() { return impl->take_fd(true); }
PortalSession::Connection PortalSession::take_eis_connection() { return impl->take_eis_connection(); }
std::future<PortalSession::Connection> PortalSession::open_pipewire_connection() { return impl->open_pipewire_connection(); }
std::future<void> PortalSession::notify_input(const Input &input) { return impl->notify_input(input); }
void PortalSession::stop() { impl->stop(); }
} // namespace traverse
