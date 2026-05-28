#pragma once
#include <chrono>
#include <deque>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>
#include "alert.h"
#include "i_detector.h"
#include "mac.h"
#include "mgmt_parser.h"

using Window = std::deque<TimePoint>;

// perSrcMac/perBssid가 동일한 통계 형태 — 한 type으로 통합. 의미 구분은 alias로.
// edge-triggered: lastAlertSeverity는 "마지막으로 알린 단계". 같은 단계는 재발사 안 함.
// count가 info 미만으로 떨어지면 nullopt로 리셋 → 새 버스트 시 다시 발사.
struct DeauthEntryStats {
    Window                       recent;
    uint64_t                     total = 0;
    TimePoint                    lastDeauthSeen;
    std::optional<AlertSeverity> lastAlertSeverity;
};
using DeauthSrcMacStats = DeauthEntryStats;
using DeauthBssidStats  = DeauthEntryStats;

struct SeverityTier {
    size_t info;
    size_t warn;
    size_t critical;
};

struct DeauthThresholds {
    SeverityTier globalRate = {50, 100, 200};   // 10s 내 deauth 총합 (raw rate)
    SeverityTier perSrcMac  = {30,  60, 100};   // 단일 송신자(addr2) burst
    SeverityTier perBssid   = {20,  50, 100};   // 한 BSS 표적 burst (가장 신뢰도 높은 신호)
};

// 생성자 인자가 5개까지 늘어나 헷갈리던 것 → 한 struct로 묶음.
// 필드 이름으로 의도 명확, 새 인자 추가해도 호출 사이트 안 깨짐.
struct DeauthDetectorConfig {
    std::chrono::milliseconds  window            = std::chrono::seconds(10);
    DeauthThresholds           thresholds;
    std::chrono::milliseconds  sourceIdleTimeout = std::chrono::minutes(5);
    std::chrono::milliseconds  removalInterval   = std::chrono::seconds(30);
};

class DeauthFloodDetector : public IDetector {
public:
    DeauthFloodDetector(DeauthDetectorConfig config = {});

    std::vector<Alert> observe(TimePoint timestamp, const ParsedFrame& frame) override;

    // 운영자 출력용 — 현재 설정된 정책을 줄 단위 vector로. caller가 indent prefix 결정.
    // banner와 진짜 정책의 drift 방지.
    std::vector<std::string> policyLines() const;


    // 순수 함수 — 단위 테스트가 직접 호출하기 위해 public static.
    static void trimWindow(Window& q, TimePoint cutoff);
    static std::optional<AlertSeverity> severityFor(size_t count, const SeverityTier& tier);

private:
    // edge-triggered: count→severity 계산 후 last보다 "올라갔을 때"만 true.
    static bool isUpwardTransition(std::optional<AlertSeverity> last, AlertSeverity current);

    // 송신자 합산은 cutoff 안 씀(observe()에서 이미 trim) — 시그니처 정직화.
    void processGlobalEvent(const ParsedFrame& frame, TimePoint now,
                            std::vector<Alert>& alerts);
    void processPerSrcMacEvent(const ParsedFrame& frame, TimePoint now, TimePoint cutoff,
                               std::vector<Alert>& alerts);
    void processPerBssidEvent(const ParsedFrame& frame, TimePoint now, TimePoint cutoff,
                              std::vector<Alert>& alerts);

    // 이전엔 anonymous namespace 자유 함수였음 — 의존 방향 정상화(class 내부로) + scope qualifier 제거.
    static bool isNormalDisconnect(std::optional<uint16_t> reason);
    static void forgetIdleEntries(std::map<Mac, DeauthEntryStats>& m,
                                  std::optional<TimePoint>&        lastRun,
                                  TimePoint                        now,
                                  std::chrono::milliseconds        interval,
                                  std::chrono::milliseconds        idleTimeout);
    static void updateEntryStats(DeauthEntryStats& stats, TimePoint now, TimePoint cutoff);

    std::chrono::milliseconds  window_;
    DeauthThresholds           thresh_;
    std::chrono::milliseconds  sourceIdleTimeout_;
    std::chrono::milliseconds  removalInterval_;

    std::mutex                                        mutex_;

    Window                                            globalEvents_;
    std::optional<AlertSeverity>                      globalLastAlertSeverity_;
    std::map<Mac, DeauthSrcMacStats>                  srcMacStats_;
    std::map<Mac, DeauthBssidStats>                   bssidStats_;
    std::optional<TimePoint>                          lastRemovalRun_;
    std::optional<TimePoint>                          lastBssidRemovalRun_;
};
