#pragma once
#include "readiness_verifier.hpp"
#include <filesystem>
#include <functional>
#include <memory>

namespace traverse {
// One client UDP endpoint, like an ordinary browser. The persistent native
// owner creates/reaps workers; an HTTP handler only drives authenticated
// signaling and waits for actual receive/cleanup evidence.
class ObserverMedia {
    struct State;
    std::unique_ptr<State> state;
  public:
    ObserverMedia(std::filesystem::path worker,std::string listen_address);
    ~ObserverMedia();
    nlohmann::json endpoint() const;
    nlohmann::json check(const ReadinessVerification &,const std::string &mode,
                         const std::string &advertised_address,unsigned short observer_port,
                         const nlohmann::json &relay,const std::function<bool()> &cancelled);
};
}
