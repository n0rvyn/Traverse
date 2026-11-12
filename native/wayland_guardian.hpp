#pragma once
#include <sys/types.h>

namespace traverse {
// Exclusive process worker. The inherited socket is its only controller;
// authority and protocol connections are created inside this process.
int wayland_guardian_worker(int controller, pid_t expected_parent);
}
