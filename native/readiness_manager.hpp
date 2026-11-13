#pragma once
#include "observer_settings.hpp"
#include <filesystem>
#include <memory>
#include <sys/types.h>

namespace traverse {
class ReadinessManager {
    struct State;
    std::unique_ptr<State> state;
  public:
    ReadinessManager(ObserverSettings settings,std::filesystem::path agent,std::string owner_socket,pid_t owner_pid,
                     unsigned short media_port=0);
    ~ReadinessManager();
    ReadinessManager(const ReadinessManager &)=delete;
    ReadinessManager &operator=(const ReadinessManager &)=delete;
    bool start();
    void invalidate();
    void controller_priority(bool active);
    void tick();
    nlohmann::json snapshot() const;
};
}
