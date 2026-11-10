#pragma once
#include "endpoint_settings.hpp"
#include <filesystem>

namespace traverse {
class HostSupervisor;
int standalone(const EndpointSettings &settings, const std::filesystem::path &binary_directory,
               const std::filesystem::path &prefix, const std::filesystem::path &runtime,
               HostSupervisor *owner = nullptr);
void turn_child(const std::filesystem::path &configuration,
                const std::filesystem::path &binary_directory);
} // namespace traverse
