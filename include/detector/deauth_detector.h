#pragma once
#include <chrono>
#include <deque>
#include <map>
#include <mutex>
#include <optional>
#include <vector>
#include "alert.h"
#include "mac.h"

struct ParsedFrame;  // forward decl — 정의는 mgmt_parser.h

// 사용 필드: ts, src, channel, reasonCode. 나머지(dst/bssid/rssi)는 CLAUDE.md
// Integration Requirements에 따라 전달되며 향후 enrichment용 reserved.
struct DeauthEvent {
    std::chrono::steady_clock::time_point ts;
    Mac                      src;
    Mac                      dst;
    Mac                      bssid;
    std::optional<int8_t>    rssi;
    std::optional<uint16_t>  reasonCode;
    std::optional<int>       channel;

    // ts는 steady_clock::now()로 자동 설정. 나머지 필드는 ParsedFrame에서 복사.
    static DeauthEvent from(const ParsedFrame& f);
};

struct DeauthSourceStats {
    std::deque<std::chrono::steady_clock::time_point>     recent;
    uint64_t                                              total      = 0;
    std::chrono::steady_clock::time_point                 lastSeen;
    // invariant: lastAlert와 lastAlertSeverity는 항상 동시 갱신.
    std::optional<std::chrono::steady_clock::time_point>  lastAlert;
    std::optional<AlertSeverity>                          lastAlertSeverity;
};

// 단위: 윈도우 안 발생 횟수. 전역 + per-source 병렬 운용 — 한쪽이 못 잡는 패턴을 다른 쪽이 backstop.
struct DeauthThresholds {
    size_t globalInfo        = 10;
    size_t globalWarn        = 20;
    size_t globalCritical    = 40;
    size_t perSourceInfo     = 5;
    size_t perSourceWarn     = 10;
    size_t perSourceCritical = 20;
};

class DeauthFloodDetector {
public:
    DeauthFloodDetector(std::chrono::milliseconds window         = std::chrono::seconds(10),
                        DeauthThresholds          thresh         = {},
                        std::chrono::milliseconds cooldown       = std::chrono::seconds(3),
                        std::chrono::milliseconds idleEvictAfter = std::chrono::minutes(5));

    // Thread-safe. 한 호출이 0~2개 alert 발사 (전역 + per-source 각 0 또는 1).
    std::vector<Alert> observe(const DeauthEvent& ev);

    size_t globalCount() const;
    size_t trackedSources() const;
    std::optional<DeauthSourceStats> statsFor(const Mac& src) const;

private:
    using TimePoint = std::chrono::steady_clock::time_point;
    using Window    = std::deque<TimePoint>;

    static void prune(Window& q, TimePoint cutoff);
    static std::optional<AlertSeverity> severityFor(size_t count, size_t infoTh, size_t warnTh, size_t critTh);

    // escalation(현재 severity > 직전)이면 cooldown 무시.
    bool shouldFire(std::optional<AlertSeverity>    lastSev,
                    AlertSeverity                   currentSev,
                    const std::optional<TimePoint>& lastAlertTime,
                    TimePoint                       now) const;

    void evictIdleSources(TimePoint now);

    std::chrono::milliseconds  window_;
    DeauthThresholds           thresh_;
    std::chrono::milliseconds  cooldown_;
    std::chrono::milliseconds  idleEvictAfter_;
    std::chrono::milliseconds  evictionInterval_{std::chrono::seconds(30)};

    // 듀얼 어댑터에서 두 capture thread가 동시 observe() 가능 → 내부 상태 보호.
    mutable std::mutex                                mtx_;

    // 전역 cooldown을 채널별로 분리 — 채널 hopping 중 다른 채널의 새 공격을 막지 않음.
    // key=-1: 채널 정보 없는 이벤트 fallback bucket.
    struct CooldownState {
        std::optional<TimePoint>     lastAlert;
        std::optional<AlertSeverity> lastAlertSeverity;
    };

    Window                                            globalEvents_;
    std::map<int, CooldownState>                      globalCooldowns_;
    std::map<Mac, DeauthSourceStats>                  sources_;
    std::optional<TimePoint>                          lastEvictionRun_;
};
