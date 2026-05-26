#pragma once
#include <chrono>
#include <cstdint>
#include <optional>
#include <type_traits>
#include <variant>
#include "mac.h"

using TimePoint = std::chrono::steady_clock::time_point;

enum class AlertSeverity { info, warn, critical };

// AlertScope는 deauth flood가 "global 합산" vs "per-source 합산" 두 차원을 동시에 갖는 데서 유래.
// 다른 디텍터(Evil Twin 등)가 scope 개념을 안 쓰면 payload에서 빼면 됨. 디텍터별 의미.
enum class AlertScope { global, perSource };

inline const char* toString(AlertSeverity s) {
    switch (s) {
        case AlertSeverity::info:     return "INFO";
        case AlertSeverity::warn:     return "WARN";
        case AlertSeverity::critical: return "CRITICAL";
    }
    return "UNKNOWN";
}

/* 디텍터별 고유 데이터는 Payload 구조체로 분리. Alert 공통 header(severity, ts, channel)만
   고정이고, payload는 std::variant로 합쳐 컴파일 타임에 타입 안전성 확보.

   새 디텍터 추가 절차:
     1) Payload 구조체 정의 (예: struct EvilTwinPayload { ... };)
     2) AlertPayload variant에 새 타입 추가
     3) categoryName()의 if constexpr 분기 추가
     4) console_log.h::format_alert의 visit 람다에 분기 추가

   variant 기반이라 별도 AlertCategory enum과 동기화 불필요 — payload type 자체가 카테고리. */

struct DeauthFloodPayload {
    AlertScope                scope;
    std::optional<Mac>        source;       // perSource인 경우만 set
    size_t                    count;        // 윈도우 내 이벤트 수
    std::chrono::milliseconds window;
    uint64_t                  total = 0;    // perSource 누적 (global은 0)
    std::optional<uint16_t>   reasonCode;   // perSource 한정
};

// 향후 추가될 payload (지금은 자리표시 주석만):
// struct EvilTwinPayload { Mac legitBssid; Mac suspectBssid; std::string ssid;
//                          std::optional<int8_t> suspectRssi; };
// struct RogueApPayload  { Mac bssid; std::optional<std::string> ssid;
//                          std::optional<int8_t> rssi; };

using AlertPayload = std::variant<DeauthFloodPayload>;

// 카테고리 이름은 payload variant에서 직접 유도 — enum 동기화 불필요.
inline const char* categoryName(const AlertPayload& p) {
    return std::visit([](const auto& v) -> const char* {
        using T = std::decay_t<decltype(v)>;
        if constexpr (std::is_same_v<T, DeauthFloodPayload>) return "deauth_flood";
        else                                                 return "unknown";
    }, p);
}

/* Alert — 데이터 전용. 공통 header + payload variant.
   format_alert(console_log.h)이 std::visit으로 payload 분기. */
struct Alert {
    AlertSeverity         severity;
    TimePoint             ts;
    std::optional<int>    channel;     // 알림 발생 시점의 채널 컨텍스트 (없을 수도 있음)
    AlertPayload          payload;
};
