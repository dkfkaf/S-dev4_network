#pragma once
#include <chrono>
#include <optional>
#include <string>
#include "mac.h"

// 순서(info < warn < critical)가 의미적 ordering — escalation 비교에 활용.
enum class AlertSeverity { info, warn, critical };

inline const char* toString(AlertSeverity s) {
    switch (s) {
        case AlertSeverity::info:     return "INFO";
        case AlertSeverity::warn:     return "WARN";
        case AlertSeverity::critical: return "CRITICAL";
    }
    return "UNKNOWN";
}

struct Alert {
    AlertSeverity                         severity;
    std::string                           message;
    std::chrono::steady_clock::time_point ts;
    std::optional<Mac>                    source;       // 전역=nullopt, per-source=해당 MAC
    size_t                                windowCount;
};
