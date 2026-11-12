#include "portal_session.hpp"
#include "input_keys.hpp"
#include "notification_probe.hpp"
#include <chrono>
#include <atomic>
#include <array>
#include <algorithm>
#include <iostream>
#include <limits>
#include <nlohmann/json.hpp>
#include <thread>
#include <vector>
using Session = traverse::PortalSession;
using Json = nlohmann::json;
namespace {
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
Session::Input event(const Json &value) {
    Session::Input input{static_cast<Session::Input::Kind>(value.at("kind").get<int>())};
    input.stream = value.value("stream", 41u);
    input.x = value.value("x", 0.0); input.y = value.value("y", 0.0);
    // JSON cannot encode NaN/infinity: explicit test-only encodings.
    if (value.value("nonfinite", "") == "nan") input.x = std::numeric_limits<double>::quiet_NaN();
    if (value.value("nonfinite", "") == "infinity") input.y = std::numeric_limits<double>::infinity();
    if (value.contains("domCode")) {
        input.kind=Session::Input::Kind::KeyboardKeycode;
        auto position=traverse::physical_key(value.at("domCode").get<std::string>());
        input.code=position ? position->evdev_code : -1;
    } else input.code = value.value("code", 0);
    input.steps = value.value("steps", 0);
    input.down = value.value("down", false);
    return input;
}
Json snapshot(Session &session) {
    auto value = session.snapshot();
    Json streams = Json::array();
    for (const auto &stream : value.streams) {
        Json row{{"node", stream.node}};
        if (stream.logical_size) row["logicalSize"] = {stream.logical_size->first, stream.logical_size->second};
        streams.push_back(std::move(row));
    }
    return {{"streams", streams}, {"waitingPermission", value.state == Session::State::WaitingPermission},
        {"notGranted", value.state == Session::State::NotGranted}, {"granted", value.state == Session::State::Granted},
        {"stopped", value.state == Session::State::Stopped}, {"closed", value.state == Session::State::Closed},
        {"failed", value.state == Session::State::Failed}, {"failure", failure_name(value.failure)},
        {"inputMethod", static_cast<int>(value.input_method)}, {"error", value.error}};
}
void wait(Session &session, bool permission) {
    const auto end = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    for (;;) {
        auto value = session.snapshot();
        if (value.state != Session::State::Probing && (!permission ||
            (value.state != Session::State::Requesting && value.state != Session::State::WaitingPermission))) return;
        if (std::chrono::steady_clock::now() >= end) throw std::runtime_error("Fixture grant watchdog expired");
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
}
}
int main(int argc, char **argv) {
    try {
        std::uint32_t devices = 3;
        bool grant = true, command_grant = false;
        if (argc == 2 && std::string(argv[1]) == "--no-grant") grant = false;
        else if (argc == 2 && std::string(argv[1]) == "--grant-command") command_grant = true;
        else if (argc == 3 && std::string(argv[1]) == "--devices") devices = std::stoul(argv[2]);
        else if (argc != 1) return 2;
        Session session;
        wait(session, false);
        if (grant) {
            if (!session.request({devices, 1, 2, false, ""})) throw std::runtime_error("Fixture grant request failed");
            if (!command_grant) wait(session, true);
        }
        std::vector<std::future<void>> futures;
        std::cout << snapshot(session) << std::endl;
        std::string line;
        while (std::getline(std::cin, line)) {
            Json command = Json::parse(line), result = Json::object();
            const auto action = command.at("action").get<std::string>();
            if (action == "notify-batch") {
                drain_notification(session.state_descriptor());
                std::vector<std::future<void>> batch;
                for (bool down : {true,false,true,false})
                    batch.push_back(session.notify_input(event({{"kind",4},{"code",30},{"down",down}})));
                // Wait on the last actual FIFO completion so several wakeup
                // bytes coalesce before the observer drains them together.
                if (batch.back().wait_for(std::chrono::seconds(5))!=std::future_status::ready)
                    throw std::runtime_error("Batch fixture watchdog expired");
                notification_until(session.state_descriptor(),[&] {
                    return std::all_of(batch.begin(),batch.end(),[](auto &future) {
                        return future.wait_for(std::chrono::seconds(0))==std::future_status::ready;
                    });
                });
                for (auto &future : batch) future.get();
                result["coalescedResults"]=batch.size();
            } else if (action == "notify-input") {
                drain_notification(session.state_descriptor());
                auto future=session.notify_input(event(command));
                notified_future(session.state_descriptor(),future);
                result["completionNotified"]=true;
                try { future.get(); result["ok"]=true; }
                catch (const Session::ConnectionError &error) { result["ok"]=false; result["inputFailure"]=failure_name(error.failure); }
            } else if (action == "notify-remote") {
                drain_notification(session.state_descriptor());
                auto future=session.open_pipewire_connection();
                notified_future(session.state_descriptor(),future);
                auto connection=future.get();
                result={{"completionNotified",true},{"valid",connection.valid()}};
            } else if (action == "notify-stop") {
                drain_notification(session.state_descriptor());
                session.stop();
                notification_until(session.state_descriptor(),[&] { return session.snapshot().state==Session::State::Stopped; });
                result["terminalNotified"]=true;
            } else if (action == "send") {
                futures.push_back(session.notify_input(event(command)));
                result["id"] = futures.size() - 1;
            } else if (action == "await") {
                auto &future = futures.at(command.at("id").get<std::size_t>());
                if (future.wait_for(std::chrono::seconds(3)) != std::future_status::ready)
                    throw std::runtime_error("Fixture input acknowledgment watchdog expired");
                try { future.get(); result["ok"] = true; }
                catch (const Session::ConnectionError &error) { result["ok"] = false; result["inputFailure"] = failure_name(error.failure); }
            } else if (action == "race-stop") {
                // Fixture-only concurrency/count, no product queue cap.
                std::array<std::vector<std::future<void>>, 4> submitted;
                std::array<std::thread, 4> threads;
                std::atomic<bool> start{false};
                for (std::size_t i = 0; i < threads.size(); ++i) threads[i] = std::thread([&, i] {
                    while (!start.load()) std::this_thread::yield();
                    for (int n = 0; n < 16; ++n)
                        submitted[i].push_back(session.notify_input(event({{"kind", 3}, {"code", 0x61}})));
                });
                start = true;
                session.stop();
                for (auto &thread : threads) thread.join();
                std::size_t settled = 0;
                for (auto &batch : submitted) for (auto &future : batch) {
                    if (future.wait_for(std::chrono::seconds(0)) != std::future_status::ready)
                        throw std::runtime_error("Concurrent Stop left unsettled input");
                    try { future.get(); }
                    catch (const Session::ConnectionError &error) {
                        if (error.failure != Session::Failure::Cancelled)
                            throw std::runtime_error("Concurrent Stop gave wrong failure");
                    }
                    ++settled;
                }
                result["settled"] = settled;
            } else if (action == "check") {
                result["resultsReady"] = Json::array();
                for (auto &future : futures) result["resultsReady"].push_back(future.valid() &&
                    future.wait_for(std::chrono::seconds(0)) == std::future_status::ready);
            } else if (action == "abandon") futures.clear();
            else if (action == "stop") session.stop();
            else return 2;
            result.update(snapshot(session));
            std::cout << result << std::endl;
        }
        session.stop();
        return 0;
    } catch (const std::exception &error) { std::cerr << error.what() << '\n'; return 1; }
}
