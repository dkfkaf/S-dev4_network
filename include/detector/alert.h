#pragma once
#include <chrono>
#include <cstdint>
#include <optional>
#include "mac.h"

using TimePoint = std::chrono::steady_clock::time_point;

enum class AlertSeverity { info, warn, critical };

enum class AlertScope { global, perSource };

inline const char* toString(AlertSeverity s) {
    switch (s) {
        case AlertSeverity::info:     return "INFO";
        case AlertSeverity::warn:     return "WARN";
        case AlertSeverity::critical: return "CRITICAL";
    }
    return "UNKNOWN";
}

struct Alert {
    AlertSeverity             severity;
    AlertScope                scope;
    TimePoint                 ts;
    std::optional<Mac>        source;
    size_t                    count;
    std::chrono::milliseconds window;
    std::optional<int>        channel;
    std::optional<uint16_t>   reasonCode;
    uint64_t                  total = 0;
};
