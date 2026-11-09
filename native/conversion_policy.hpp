#pragma once
#include <sched.h>

namespace traverse {
inline unsigned conversion_threads() {
    cpu_set_t allowed;
    CPU_ZERO(&allowed);
    if (sched_getaffinity(0, sizeof(allowed), &allowed) != 0) return 1;
    return CPU_COUNT(&allowed) >= 2 ? 2U : 1U;
}
}
