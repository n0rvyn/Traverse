#pragma once
#include <functional>
#include <nlohmann/json.hpp>

namespace traverse {
// Private inherited-channel protocol. Events contain receipts, never bearers.
void run_readiness_agent(const nlohmann::json &request,
                         const std::function<void(const nlohmann::json &)> &emit);
}
