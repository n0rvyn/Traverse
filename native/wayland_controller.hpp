#pragma once
#include <future>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <sys/types.h>
#include <nlohmann/json.hpp>

namespace traverse {
class WaylandController {
    struct Impl;
  public:
    enum class Failure { Cancelled, Spawn, Protocol, Transport, ChildExit };
    struct Error : std::runtime_error {
        Failure failure;
        Error(Failure kind,const std::string &reason):std::runtime_error(reason),failure(kind) {}
    };
    struct Snapshot {
        // Historical native state is separate from current owner admission.
        std::optional<nlohmann::json> desktop;
        pid_t worker_pid=-1;
        bool accepting=false,terminal=false;
        std::optional<int> exit_status;
        std::string error;
        bool input_ready() const {
            return accepting && desktop && desktop->value("inputReady",false);
        }
    };
    // Trusted absolute worker path; inherit the owner's already prepared
    // package environment. Capability discovery grants no desktop permission.
    explicit WaylandController(std::string worker_path);
    ~WaylandController() noexcept;
    WaylandController(const WaylandController &)=delete;
    WaylandController &operator=(const WaylandController &)=delete;
    // Object containing op and its arguments. Identity/schema are generated
    // here. Native ok:false is preserved; transport failures throw Error.
    std::future<nlohmann::json> request(nlohmann::json command);
    // Stops admission immediately. Ready only after replies settle and the
    // exact child is reaped. Safe to call repeatedly; destruction also stops.
    std::shared_future<void> stop();
    Snapshot snapshot() const;
    // Borrowed until destruction; coalesced state AND completion wakeups.
    // Drain then inspect snapshots/futures; descriptors survive Stop.
    int state_descriptor() const noexcept;
  private:
    std::unique_ptr<Impl> impl;
};
}
