#pragma once
#include <chrono>
#include <cstdint>
#include <optional>
#include "mac.h"

using TimePoint = std::chrono::steady_clock::time_point;

enum class AlertSeverity { info, warn, critical };

// AlertScope는 deauth flood의 카운트 차원:
//   globalRate — 모든 deauth 합산 (raw rate, broadcast 공격 백스톱)
//   perSrcMac  — 송신자(802.11 addr2) MAC별 (단일 attacker)
//   perBssid   — 표적 BSSID별 (MAC randomization 우회 — 진짜 표적이 어디인지)
// 다른 디텍터(Evil Twin 등)는 scope 개념 다르게 쓰거나 안 쓸 수 있음.
enum class AlertScope { globalRate, perSrcMac, perBssid };

inline const char* toString(AlertSeverity s) {
    switch (s) {
        case AlertSeverity::info:     return "INFO";
        case AlertSeverity::warn:     return "WARN";
        case AlertSeverity::critical: return "CRITICAL";
    }
    return "UNKNOWN";
}

// 현재 디텍터가 DeauthFloodDetector 하나뿐 — std::variant<DeauthFloodPayload>는 single-alternative
// dead complexity였음. payload를 그냥 DeauthFloodPayload로 직접 사용.
// 향후 Evil Twin 등 추가 시 variant 재도입 또는 다른 polymorphism 메커니즘 결정.
struct DeauthFloodPayload {
    AlertScope                scope;
    std::optional<Mac>        srcMac;        // perSrcMac: 송신자 MAC (802.11 addr2)
    std::optional<Mac>        bssid;         // perBssid: 표적 BSS, perSrcMac: 최근 표적 context
    std::optional<int8_t>     rssi;          // perSrcMac/perBssid: 최근 RSSI (운영자 판단용)
    size_t                    count;         // 윈도우 내 이벤트 수
    std::chrono::milliseconds window;
    uint64_t                  total = 0;     // perSrcMac/perBssid 누적 (global은 0)
    std::optional<uint16_t>   reasonCode;    // perSrcMac/perBssid: 최근 reason code
};

inline const char* categoryName(const DeauthFloodPayload&) {
    return "deauth_flood";
}

/* Alert — 데이터 전용. 단일 payload type (DeauthFloodPayload). */
struct Alert {
    AlertSeverity         severity;
    std::optional<int>    channel;     // 알림 발생 시점의 채널 컨텍스트 (없을 수도 있음)
    DeauthFloodPayload    payload;
};
