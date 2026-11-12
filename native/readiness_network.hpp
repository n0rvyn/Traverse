#pragma once
#include <memory>
#include <string>
#include <vector>

namespace traverse {
class ReadinessNetwork {
    struct State;
    std::unique_ptr<State> state;
  public:
    struct Observation {bool changed;bool healthy;};
    explicit ReadinessNetwork(std::vector<std::string> files={"/etc/resolv.conf","/etc/hosts","/etc/nsswitch.conf","/etc/gai.conf"});
    ~ReadinessNetwork();
    ReadinessNetwork(const ReadinessNetwork &)=delete;
    ReadinessNetwork &operator=(const ReadinessNetwork &)=delete;
    Observation poll();
};
}
