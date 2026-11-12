#include "portal_session.hpp"
#include "capture_backend.hpp"
#include <gst/gst.h>
#include <chrono>
#include <cerrno>
#include <atomic>
#include <fcntl.h>
#include <iostream>
#include <nlohmann/json.hpp>
#include <poll.h>
#include <set>
#include <csignal>
#include <sys/wait.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
using Session = traverse::PortalSession;
using Json = nlohmann::json;
namespace {
struct OwnedFd {
    int value;
    explicit OwnedFd(int fd) : value(fd) {}
    ~OwnedFd() { if (value >= 0) close(value); }
    OwnedFd(const OwnedFd &) = delete;
    OwnedFd &operator=(const OwnedFd &) = delete;
    operator int() const { return value; }
};
const char *failure_name(Session::Failure value) {
    switch (value) {
        case Session::Failure::None: return "none";
        case Session::Failure::Unavailable: return "unavailable";
        case Session::Failure::Cancelled: return "cancelled";
        case Session::Failure::Transport: return "transport";
        case Session::Failure::Method: return "method";
        case Session::Failure::InvalidResponse: return "invalid-response";
        case Session::Failure::InvalidInput: return "invalid-input";
    }
    return "unknown";
}
Json report(const Session::Snapshot &value) {
    Json streams = Json::array();
    for (const auto &stream : value.streams) {
        Json row{{"node", stream.node}};
        if (stream.serial) row["serial"] = *stream.serial;
        if (stream.source_type) row["sourceType"] = *stream.source_type;
        if (stream.logical_size) row["logicalSize"] = {stream.logical_size->first, stream.logical_size->second};
        if (stream.position) row["position"] = {stream.position->first, stream.position->second};
        if (stream.mapping_id) row["mappingId"] = *stream.mapping_id;
        streams.push_back(std::move(row));
    }
    return {{"ready", value.state == Session::State::CapabilitiesReady},
        {"granted", value.state == Session::State::Granted}, {"stopped", value.state == Session::State::Stopped},
        {"closed", value.state == Session::State::Closed}, {"notGranted", value.state == Session::State::NotGranted},
        {"waitingPermission", value.state == Session::State::WaitingPermission},
        {"uid", getuid()}, {"remoteVersion", value.remote_version}, {"screenVersion", value.screen_version},
        {"devices", value.devices}, {"sources", value.sources},
        {"cursorModes", value.cursor_modes ? Json(*value.cursor_modes) : Json(nullptr)},
        {"portalResponse", value.portal_response ? Json(*value.portal_response) : Json(nullptr)},
        {"inputMethod", value.input_method == Session::InputMethod::Eis ? "eis" : value.input_method == Session::InputMethod::PortalDbus ? "portal-dbus" : "undetermined"},
        {"failure", failure_name(value.failure)},
        {"grantedDevices", value.granted_devices}, {"streams", streams}, {"error", value.error}};
}
Session::Snapshot wait(Session &session, bool permissions) {
    // Only the standalone test probe has a watchdog. The module does not time
    // out user permission decisions and can always be explicitly stopped.
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    for (;;) {
        auto value = session.snapshot();
        bool waiting = value.state == Session::State::Probing ||
            (permissions && (value.state == Session::State::Requesting || value.state == Session::State::WaitingPermission));
        if (!waiting) return value;
        if (std::chrono::steady_clock::now() >= deadline) throw std::runtime_error("Native probe watchdog expired");
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
}
bool unavailable(Session &session) {
    try { int fd = session.take_pipewire_fd(); close(fd); return false; }
    catch (const std::exception &) { return true; }
}
bool marker(int fd, unsigned char expected) {
    pollfd item{fd, POLLIN, 0};
    unsigned char byte = 0;
    return poll(&item, 1, 2000) > 0 && read(fd, &byte, 1) == 1 && byte == expected;
}
bool eof(int fd) {
    pollfd item{fd, POLLIN | POLLHUP, 0};
    unsigned char byte = 0;
    return poll(&item, 1, 2000) > 0 && read(fd, &byte, 1) == 0;
}
}
int main(int argc, char **argv) {
    try {
        const std::string mode = argc == 2 ? argv[1] : "";
        if (argc > 2 || (!mode.empty() && mode != "--command" && mode != "--grant" &&
            mode != "--grant-fixture" && mode != "--grant-multiple-fixture" && mode != "--grant-command" && mode != "--grant-observe-close" && mode != "--grant-connections-fixture" && mode != "--grant-connections-command" && mode != "--grant-connections-stop-race" && mode != "--grant-eis-lease" && mode != "--grant-eis-raw-first" && mode != "--grant-eis-take-race")) return 2;
        Session session;
        if (mode == "--command") {
            std::string command;
            if (!std::getline(std::cin, command) || command != "stop") return 2;
            session.stop(); auto value = session.snapshot();
            auto output = report(value); output["grantOrCaptureRequested"] = false;
            std::cout << output << '\n';
            return value.state == Session::State::Stopped ? 0 : 1;
        }
        auto value = wait(session, false);
        if (mode.empty() || value.state != Session::State::CapabilitiesReady) {
            auto output = report(value); output["grantOrCaptureRequested"] = false;
            session.stop(); std::cout << output << '\n';
            return value.state == Session::State::CapabilitiesReady ? 0 : 1;
        }
        bool initially_unavailable = unavailable(session);
        bool eis_before_denied = false;
        if (mode == "--grant-eis-lease") {
            try { auto lease = session.take_eis_connection(); }
            catch (const Session::ConnectionError &error) { eis_before_denied = error.failure == Session::Failure::Unavailable; }
        }
        bool future_before_grant_denied = false;
        if (mode == "--grant-connections-fixture") {
            try { auto connection = session.open_pipewire_connection().get(); }
            catch (const Session::ConnectionError &error) { future_before_grant_denied = error.failure == Session::Failure::Unavailable; }
        }
        if (!session.request({3, 1, 2, mode == "--grant-multiple-fixture", ""})) throw std::runtime_error("Explicit test selection unavailable");
        if (mode == "--grant-command") {
            std::string command;
            bool stopped = false;
            while (std::getline(std::cin, command)) {
                if (command == "stop") { session.stop(); stopped = true; }
                else if (command != "check") return 2;
                auto output = report(session.snapshot()); output["grantOrCaptureRequested"] = true;
                if (stopped) output["descriptorsUnavailableAfterStop"] = unavailable(session);
                std::cout << output << std::endl;
            }
            return stopped && session.snapshot().state == Session::State::Stopped ? 0 : 1;
        }
        value = wait(session, true);
        auto output = report(value); output["grantOrCaptureRequested"] = true;
        output["descriptorsUnavailableBeforeGrant"] = initially_unavailable;
        if (value.state != Session::State::Granted) {
            session.stop(); output["descriptorsUnavailableAfterStop"] = unavailable(session);
            std::cout << output << '\n'; return 1;
        }
        if (mode == "--grant-eis-raw-first") {
            OwnedFd raw(session.take_eis_fd());
            bool denied = false;
            try { auto lease = session.take_eis_connection(); }
            catch (const Session::ConnectionError &error) { denied = error.failure == Session::Failure::Unavailable; }
            output["ownedTransferDeniedAfterRaw"] = denied;
            output["grantPreserved"] = session.snapshot().state == Session::State::Granted;
            session.stop();
            std::cout << output << std::endl;
            return denied && output["grantPreserved"].get<bool>() ? 0 : 1;
        }
        if (mode == "--grant-eis-take-race") {
            auto capture = session.open_pipewire_connection().get();
            Session::Connection input;
            std::atomic<bool> ready{false};
            std::thread stopper([&] { while (!ready.load()) std::this_thread::yield(); session.stop(); });
            ready = true;
            bool cancelled = false;
            try { input = session.take_eis_connection(); }
            catch (const Session::ConnectionError &error) { cancelled = error.failure == Session::Failure::Cancelled; }
            stopper.join();
            auto final = report(session.snapshot());
            final["raceSettled"] = (cancelled || input.protocol() == Session::Connection::Protocol::Eis) &&
                !input.valid() && !capture.valid() && fcntl(capture.descriptor(), F_GETFD) >= 0;
            std::cout << final << std::endl;
            return final["stopped"].get<bool>() && final["raceSettled"].get<bool>() ? 0 : 1;
        }
        if (mode == "--grant-eis-lease") {
            auto capture = session.open_pipewire_connection().get();
            bool wrong_method_denied = false;
            if (value.input_method != Session::InputMethod::Eis) {
                try { auto lease = session.take_eis_connection(); }
                catch (const Session::ConnectionError &error) { wrong_method_denied = error.failure == Session::Failure::Unavailable; }
                output["wrongMethodDenied"] = wrong_method_denied;
                output["grantPreserved"] = capture.valid() && session.snapshot().state == Session::State::Granted;
                session.stop();
                std::cout << output << std::endl;
                return wrong_method_denied && output["grantPreserved"].get<bool>() ? 0 : 1;
            }
            auto original = session.take_eis_connection();
            Session::Connection moved(std::move(original)), held;
            held = std::move(moved);
            bool move_safe = !original.valid() && !moved.valid() && held.valid() &&
                original.protocol() == Session::Connection::Protocol::None &&
                moved.protocol() == Session::Connection::Protocol::None;
            bool raw_denied = false, owned_denied = false;
            try { OwnedFd duplicate(session.take_eis_fd()); }
            catch (const std::exception &) { raw_denied = true; }
            try { auto duplicate = session.take_eis_connection(); }
            catch (const Session::ConnectionError &) { owned_denied = true; }
            bool typed = held.protocol() == Session::Connection::Protocol::Eis &&
                capture.protocol() == Session::Connection::Protocol::PipeWire;
            output["beforeGrantDenied"] = eis_before_denied;
            output["movesPreserveSoleConsumer"] = move_safe;
            output["rawAndOwnedSecondTransfersDenied"] = raw_denied && owned_denied;
            output["connectionsHaveCorrectProtocol"] = typed;
            std::cout << output << std::endl;
            std::string command;
            if (!std::getline(std::cin, command)) return 2;
            bool operation_ok = true;
            if (command == "drop") held = {};
            else if (command == "stop") session.stop();
            else if (command == "closed") {} // fixture emits Session.Closed
            else if (command == "wrong-protocol") {
                gst_init(nullptr, nullptr);
                operation_ok = false;
                try {
                    traverse::PipeWireCapture invalid(std::move(held), value.streams.front(),
                        {"/tmp", "video/x-raw,format=I420,framerate=60/1"});
                } catch (const std::invalid_argument &) { operation_ok = true; }
            }
            else if (command == "race") {
                std::thread stopper([&] { session.stop(); });
                held = {};
                stopper.join();
            } else if (command == "consumer-kill") {
                pid_t child = fork();
                if (child < 0) throw std::runtime_error("Consumer fork failed");
                if (child == 0) { for (;;) pause(); }
                held = {};
                operation_ok = session.snapshot().state == Session::State::Granted && capture.valid();
                int status = 0;
                kill(child, SIGKILL);
                while (waitpid(child, &status, 0) < 0) { if (errno != EINTR) throw std::runtime_error("Consumer reap failed"); }
                operation_ok = operation_ok && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL;
            } else return 2;
            auto end = std::chrono::steady_clock::now() + std::chrono::seconds(5);
            while (session.snapshot().state == Session::State::Granted && std::chrono::steady_clock::now() < end)
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            auto terminal = session.snapshot();
            auto final = report(terminal);
            final["captureRevokedWhileDescriptorHeld"] = !capture.valid() && fcntl(capture.descriptor(), F_GETFD) >= 0;
            final["portalClosedPeer"] = eof(capture.descriptor());
            final["consumerOperationPassed"] = operation_ok;
            bool after_denied = false;
            try { auto lease = session.take_eis_connection(); }
            catch (const Session::ConnectionError &error) {
                after_denied = error.failure == (command == "closed" ? Session::Failure::Unavailable : Session::Failure::Cancelled);
            }
            final["afterStopDenied"] = after_denied;
            final["heldEisRevoked"] = !held.valid();
            std::cout << final << std::endl;
            session.stop();
            return eis_before_denied && move_safe && raw_denied && owned_denied && typed && operation_ok &&
                (command == "closed" ? terminal.state == Session::State::Closed : terminal.state == Session::State::Stopped) &&
                final["captureRevokedWhileDescriptorHeld"].get<bool>() &&
                final["portalClosedPeer"].get<bool>() && after_denied && !held.valid() ? 0 : 1;
        }
        if (mode == "--grant-connections-command" || mode == "--grant-connections-stop-race") {
            std::vector<Session::Connection> held;
            auto initial = session.open_pipewire_connection();
            if (initial.wait_for(std::chrono::seconds(5)) != std::future_status::ready)
                throw std::runtime_error("Initial connection watchdog expired");
            held.push_back(initial.get());
            std::vector<std::future<Session::Connection>> pending;
            if (mode == "--grant-connections-stop-race") {
                // Test stress count only, no runtime queue/count limit.
                for (int i = 0; i < 64; ++i) pending.push_back(session.open_pipewire_connection());
                session.stop();
                bool settled = true, revoked = !held.front().valid();
                for (auto &future : pending) {
                    settled = settled && future.wait_for(std::chrono::seconds(0)) == std::future_status::ready;
                    if (!settled) break;
                    try { auto connection = future.get(); revoked = revoked && !connection.valid(); }
                    catch (const Session::ConnectionError &error) { revoked = revoked && error.failure == Session::Failure::Cancelled; }
                }
                auto result = report(session.snapshot()); result["allFuturesSettled"] = settled;
                result["allConnectionsRevoked"] = revoked; std::cout << result << std::endl;
                return settled && revoked ? 0 : 1;
            }
            auto initial_report = report(session.snapshot()); initial_report["heldConnectionsValid"] = held.front().valid();
            std::cout << initial_report << std::endl;
            std::string command;
            bool stopped = false;
            while (std::getline(std::cin, command)) {
                Json details = Json::object();
                if (command == "open") pending.push_back(session.open_pipewire_connection());
                else if (command == "stop") { session.stop(); stopped = true; }
                else if (command == "get") {
                    if (pending.empty() || !pending.back().valid()) throw std::runtime_error("No pending result");
                    if (pending.back().wait_for(std::chrono::seconds(5)) != std::future_status::ready)
                        throw std::runtime_error("Connection result watchdog expired");
                    try { held.push_back(pending.back().get()); details["connectionFailure"] = "none"; }
                    catch (const Session::ConnectionError &error) { details["connectionFailure"] = failure_name(error.failure); }
                    pending.pop_back();
                } else if (command == "drop") {
                    if (pending.empty()) throw std::runtime_error("No result to abandon");
                    pending.pop_back(); details["dropped"] = true;
                } else if (command != "check") return 2;
                auto result = report(session.snapshot()); result.update(details);
                bool all_valid = true, settled = true;
                for (const auto &connection : held) all_valid = all_valid && connection.valid();
                for (auto &future : pending) settled = settled && future.wait_for(std::chrono::seconds(0)) == std::future_status::ready;
                result["heldConnectionsValid"] = all_valid; result["allFuturesSettled"] = settled;
                std::cout << result << std::endl;
            }
            return stopped && session.snapshot().state == Session::State::Stopped ? 0 : 1;
        }
        if (mode == "--grant-connections-fixture") {
            std::vector<std::future<Session::Connection>> pending;
            for (int i = 0; i < 3; ++i) pending.push_back(session.open_pipewire_connection());
            std::vector<Session::Connection> held;
            std::set<ino_t> identities;
            bool cloexec = true, valid = true;
            for (auto &future : pending) {
                if (future.wait_for(std::chrono::seconds(5)) != std::future_status::ready)
                    throw std::runtime_error("Connection probe watchdog expired");
                held.push_back(future.get());
                auto &connection = held.back();
                struct stat identity{};
                if (fstat(connection.descriptor(), &identity)) throw std::runtime_error("Connection identity unavailable");
                identities.insert(identity.st_ino);
                valid = valid && connection.valid();
                for (int fd : {connection.descriptor(), connection.revocation_descriptor()}) {
                    int flags = fcntl(fd, F_GETFD);
                    cloexec = cloexec && flags >= 0 && (flags & FD_CLOEXEC);
                }
            }
            {
                auto abandoned = session.open_pipewire_connection();
                if (abandoned.wait_for(std::chrono::seconds(5)) != std::future_status::ready)
                    throw std::runtime_error("Abandoned result watchdog expired");
                // No get(): destroying the future must close the fulfilled FD.
            }
            output["beforeGrantDenied"] = future_before_grant_denied;
            output["distinctConnections"] = identities.size();
            output["allValidBeforeStop"] = valid;
            output["connectionsCloexec"] = cloexec;
            std::cout << output << std::endl;
            std::string command;
            if (!std::getline(std::cin, command) || command != "stop") return 2;
            session.stop();
            bool revoked = true, retained = true, after_denied = false;
            for (const auto &connection : held) {
                revoked = revoked && !connection.valid();
                retained = retained && fcntl(connection.descriptor(), F_GETFD) >= 0;
            }
            char byte = 0;
            bool persistent = read(held.front().revocation_descriptor(), &byte, 1) == 0;
            for (const auto &connection : held) persistent = persistent && !connection.valid();
            try { auto connection = session.open_pipewire_connection().get(); }
            catch (const Session::ConnectionError &error) { after_denied = error.failure == Session::Failure::Cancelled; }
            auto final = report(session.snapshot());
            final["allConnectionsRevoked"] = revoked;
            final["connectionDescriptorsStillOwned"] = retained;
            final["revocationBroadcastPersistsAfterRead"] = persistent;
            final["afterStopDenied"] = after_denied;
            std::cout << final << std::endl;
            return future_before_grant_denied && identities.size() == 3 && valid && cloexec && revoked && retained && persistent && after_denied ? 0 : 1;
        }
        OwnedFd capture(session.take_pipewire_fd());
        OwnedFd input(value.input_method == Session::InputMethod::Eis ? session.take_eis_fd() : -1);
        output["connectionTransfersExactlyOnce"] = unavailable(session);
        if (input >= 0) {
            try { int duplicate = session.take_eis_fd(); close(duplicate); output["connectionTransfersExactlyOnce"] = false; }
            catch (const std::exception &) {}
        }
        const int capture_flags = fcntl(capture, F_GETFD), input_flags = input < 0 ? 0 : fcntl(input, F_GETFD);
        bool cloexec = capture_flags >= 0 && (capture_flags & FD_CLOEXEC) &&
            (input < 0 || (input_flags >= 0 && (input_flags & FD_CLOEXEC)));
        output["exportedDescriptorsCloexec"] = cloexec;
        if (mode == "--grant-observe-close") {
            std::cout << output << std::endl;
            auto end = std::chrono::steady_clock::now() + std::chrono::seconds(10);
            while (session.snapshot().state == Session::State::Granted && std::chrono::steady_clock::now() < end)
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            auto closed = session.snapshot();
            output = report(closed);
            output["grantOrCaptureRequested"] = true;
            output["exportedDescriptorsCloexec"] = cloexec;
            output["sessionClosedObserved"] = closed.state == Session::State::Closed;
        }
        bool proof = true;
        const bool fixture = mode == "--grant-fixture" || mode == "--grant-multiple-fixture";
        if (fixture) {
            // Controlled socket-pair markers only; real desktop runs never read
            // arbitrary PipeWire/EIS data or serialize any of its contents.
            proof = marker(capture, 0x5a) && (input < 0 || marker(input, 0x45));
            output["actualTransferredSocketMarkersMatched"] = proof;
        }
        session.stop();
        output["descriptorsUnavailableAfterStop"] = unavailable(session);
        if (fixture) {
            bool revoked = eof(capture) && (input < 0 || eof(input));
            output["authorityRevokedWhileConsumerDescriptorsRemain"] = revoked;
            proof = proof && revoked;
        }
        std::cout << output << '\n';
        return cloexec && proof && output["descriptorsUnavailableAfterStop"].get<bool>() &&
            (mode != "--grant-observe-close" || output["sessionClosedObserved"].get<bool>()) ? 0 : 1;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n'; return 1;
    }
}
