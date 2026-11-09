#pragma once
#include "endpoint_settings.hpp"
#include <filesystem>

namespace traverse {
int standalone(const EndpointSettings &settings, const std::filesystem::path &binary_directory,
               const std::filesystem::path &prefix, const std::filesystem::path &runtime);
void turn_child(const std::filesystem::path &configuration,
                const std::filesystem::path &binary_directory);
} // namespace traverse
