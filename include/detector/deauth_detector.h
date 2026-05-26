#pragma once
#include <chrono>
#include <deque>
#include <map>
#include <mutex>
#include <optional>
#include <vector>
#include "alert.h"
#include "i_detector.h"
#include "mac.h"
#include "mgmt_parser.h"

using Window = std::deque<TimePoint>;

struct CooldownState {
    std::optional<TimePoint>     lastAlert;
    std::optional<AlertSeverity> lastAlertSeverity;
};

// perSrcMac/perBssid가 동일한 통계 형태 — 한 type으로 통합. 의미 구분은 alias로.
struct DeauthEntryStats {
    Window         recent;
    uint64_t       total = 0;
    TimePoint      lastDeauthSeen;
    CooldownState  state;
};
using DeauthSrcMacStats = DeauthEntryStats;
using DeauthBssidStats  = DeauthEntryStats;

struct SeverityTier {
    size_t info;
    size_t warn;
    size_t critical;
};

// 임계치 상향 — 이전 기본값(10/20/40 globalRate, 5/10/20 perSrcMac)은 정상 핸드폰 활동을
// CRITICAL로 잘못 분류. 진짜 flood는 초당 수십~수백개라 새 값으로도 즉시 critical.
struct DeauthThresholds {
    SeverityTier globalRate = {50, 100, 200};   // 10s에 5/10/20건/s 도달 시 단계
    SeverityTier perSrcMac  = {30, 60, 100};    // 단일 송신자(addr2) burst
    SeverityTier perBssid   = {20, 50, 100};    // 한 BSS 표적 burst (가장 신뢰도 높은 신호)
};

class DeauthFloodDetector : public IDetector {
public:
    DeauthFloodDetector(std::chrono::milliseconds window            = std::chrono::seconds(10),
                        DeauthThresholds          thresh            = {},
                        std::chrono::milliseconds cooldown          = std::chrono::seconds(3),
                        std::chrono::milliseconds sourceIdleTimeout = std::chrono::minutes(5),
                        std::chrono::milliseconds removalInterval   = std::chrono::seconds(30));

    const char* name() const override { return "deauth_flood"; }

    std::vector<Alert> observe(TimePoint timestamp, const ParsedFrame& frame) override;

    // 운영자 출력용 — 현재 설정된 임계치/윈도우를 한 줄 요약. banner와 진짜 정책의 drift 방지.
    std::string policySummary() const;

    size_t globalCount() const;
    size_t trackedSrcMacs() const;
    size_t trackedBssids() const;
    std::optional<DeauthSrcMacStats> statsFor(const Mac& srcMac) const;
    std::optional<DeauthBssidStats>  bssidStatsFor(const Mac& bssid) const;

    // 순수 함수 — 단위 테스트가 직접 호출하기 위해 public static.
    static void trimWindow(Window& q, TimePoint cutoff);
    static std::optional<AlertSeverity> severityFor(size_t count, const SeverityTier& tier);

private:
    bool shouldAlert(const CooldownState& state, AlertSeverity currentSeverity, TimePoint now) const;

    void processGlobalEvent(const ParsedFrame& frame, TimePoint now, TimePoint cutoff,
                            std::vector<Alert>& alerts);
    void processPerSrcMacEvent(const ParsedFrame& frame, TimePoint now, TimePoint cutoff,
                               std::vector<Alert>& alerts);
    void processPerBssidEvent(const ParsedFrame& frame, TimePoint now, TimePoint cutoff,
                              std::vector<Alert>& alerts);

    void forgetIdleSrcMacs(TimePoint now);
    void forgetIdleBssids(TimePoint now);

    std::chrono::milliseconds  window_;
    DeauthThresholds           thresh_;
    std::chrono::milliseconds  cooldown_;
    std::chrono::milliseconds  sourceIdleTimeout_;
    std::chrono::milliseconds  removalInterval_;

    mutable std::mutex                                mutex_;

    Window                                            globalEvents_;
    CooldownState                                     globalCooldown_;
    std::map<Mac, DeauthSrcMacStats>                  srcMacStats_;
    std::map<Mac, DeauthBssidStats>                   bssidStats_;
    std::optional<TimePoint>                          lastRemovalRun_;
    std::optional<TimePoint>                          lastBssidRemovalRun_;
};
