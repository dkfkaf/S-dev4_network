#include "pch.h"
#include "deauth_detector.h"
#include "dot11.h"
#include <algorithm>

DeauthFloodDetector::DeauthFloodDetector(std::chrono::milliseconds window,
                                         DeauthThresholds          thresh,
                                         std::chrono::milliseconds cooldown,
                                         std::chrono::milliseconds sourceIdleTimeout)
    : window_(window),
      thresh_(thresh),
      cooldown_(cooldown),
      sourceIdleTimeout_(sourceIdleTimeout) {}

/* trimWindow — deque에서 윈도우 밖(=옛날) timestamp 제거.
   cutoff = "위치"가 아니라 "시간 값" — 윈도우의 가장 오래된 허용 시각 (= now - window_).
   deque는 시간순 정렬 (front=가장 옛날, back=가장 최근).
   front가 cutoff보다 옛날이면 윈도우 밖 → pop_front.
   front가 cutoff 이후면 그 뒤는 다 윈도우 안이라 멈춤 (정렬 가정 활용 → amortized O(1)). */
void DeauthFloodDetector::trimWindow(Window& q, TimePoint cutoff) {
    while (!q.empty() && q.front() < cutoff) q.pop_front();
}

std::optional<AlertSeverity> DeauthFloodDetector::severityFor(size_t count,
                                                              const SeverityTier& tier) {
    if (count >= tier.critical) return AlertSeverity::critical;
    if (count >= tier.warn)     return AlertSeverity::warn;
    if (count >= tier.info)     return AlertSeverity::info;
    return std::nullopt;
}

/* shouldAlert — cooldown + escalation 룰로 alert 발사 여부 판단.
   - 첫 alert (lastAlert 없음) → 무조건 발사
   - escalation (현재 > 이전 severity) → cooldown 무시하고 즉시 발사
   - 같거나 낮은 severity → cooldown 적용 (마지막 alert 이후 cooldown_ 지나야 발사) */
bool DeauthFloodDetector::shouldAlert(const CooldownState& cd,
                                      AlertSeverity        currentSev,
                                      TimePoint            now) const {
    if (!cd.lastAlert.has_value()) return true;
    if (currentSev > cd.lastAlertSeverity.value()) return true;
    return (now - cd.lastAlert.value()) >= cooldown_;
}

/* forgetIdleSources — 오래 안 보인 source를 sources_ 맵에서 제거 (메모리 관리).

   [Throttle] 이전 실행 후 30초(removalInterval_) 안 지났으면 그냥 return.
   "< 30초면 수행 안 함" — 30초마다 한 번만 실제 스캔.
   매 observe()마다 호출되는데 매번 전체 맵 스캔하면 비효율.

   [Erase 조건] AND (둘 다 만족해야 erase):
     ① recent.empty()                  — 윈도우(10초) 안 활동 0건
     ② (now - lastDeauthSeen) > 5분    — 마지막 deauth가 5분 이상 전
   "윈도우도 비었고 + 오래 안 봄" = 진짜 idle. 한 조건만으론 부족 → ||가 아니라 &&.
   주의: 30초(throttle 주기) ≠ 5분(idle 임계치) — 두 시간 단위가 다른 일을 함. */
void DeauthFloodDetector::forgetIdleSources(TimePoint now) {
    if (lastRemovalRun_.has_value() &&
        (now - lastRemovalRun_.value()) < removalInterval_) return;
    lastRemovalRun_ = now;

    for (auto it = sources_.begin(); it != sources_.end(); ) {
        const auto& stats = it->second;
        if (stats.recent.empty() && (now - stats.lastDeauthSeen) > sourceIdleTimeout_) {
            it = sources_.erase(it);
        } else {
            ++it;
        }
    }
}

/* globalCount / trackedSources / statsFor — 외부 모니터링/디버깅용 스냅샷 조회.
   sources_/globalEvents_는 observe()가 동시 수정 가능한 공유 상태 → 읽기도 락 필수.
   mtx_가 mutable인 이유: const 메서드에서도 락 잡아야 해서. */
size_t DeauthFloodDetector::globalCount() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return globalEvents_.size();
}

size_t DeauthFloodDetector::trackedSources() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return sources_.size();
}

/* statsFor — 특정 src의 통계 스냅샷 반환 (없으면 nullopt).
   std::map의 element는 (key, value) pair 구조:
     it->first  = key   → Mac 주소 (호출자가 이미 아는 src와 동일)
     it->second = value → DeauthSourceStats (이게 우리가 원하는 통계)
   map 특화 이름 아니라 std::pair의 표준 멤버명. */
std::optional<DeauthSourceStats> DeauthFloodDetector::statsFor(const Mac& src) const {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = sources_.find(src);
    if (it == sources_.end()) return std::nullopt;
    return it->second;
}

/* observe — IDetector 인터페이스 진입점. deauth가 아닌 frameType은 즉시 빈 vector.
   deauth일 때 0~2개 alert 반환 (전역 + per-source).

   [Lock] mtx_로 thread-safe 진입. 듀얼 어댑터에서 두 capture thread가 동시 호출 가능.

   [시간 거꾸로 가는 거 방지]
   듀얼 어댑터에서 다른 thread가 이미 더 늦은 ts를 먼저 push 했으면, 이 frame의 ts도
   그 값으로 올려서 deque가 시간 순으로 정렬되게 유지.
   (정렬 깨지면 trimWindow가 잘못 동작 — 앞쪽이 옛날, 뒤쪽이 최신이라고 가정하기 때문)

   [흐름]
     1) processGlobalEvent     — 모든 deauth 통합 카운트 갱신 + 임계치 넘으면 global alert
     2) processPerSourceEvent  — src별 deauth 카운트 갱신 + 임계치 넘으면 per-source alert
     3) forgetIdleSources      — 오래된 src 잊기 (메모리 청소) */
std::vector<Alert> DeauthFloodDetector::observe(TimePoint ts, const ParsedFrame& frame) {
    if (frame.frameType != MGMT_SUBTYPE_DEAUTH) return {};

    std::lock_guard<std::mutex> lock(mtx_);
    std::vector<Alert> alerts;

    const TimePoint now = globalEvents_.empty()
        ? ts
        : std::max(ts, globalEvents_.back());
    const TimePoint cutoff = now - window_;

    processGlobalEvent(frame, now, cutoff, alerts);
    processPerSourceEvent(frame, now, cutoff, alerts);
    forgetIdleSources(now);

    return alerts;
}

/* processGlobalEvent — 전역 차원: 모든 채널 합산 윈도우 갱신 + 채널별 cooldown 적용한 alert.

   [gcd = "참조 가져오기", NOT "세팅"]
   CooldownState& gcd = globalCooldowns_[channelKey] 는 그 채널의 cooldown 슬롯을 reference로 받음.
   없는 channelKey면 CooldownState{} 기본값(둘 다 nullopt)으로 자동 생성 (map::operator[] 특성).
   gcd는 맵 안 값의 별칭 — gcd 수정하면 맵 안 값이 직접 바뀜.

   [Cooldown 갱신 — 함수 끝부분]
   gcd.lastAlert/lastAlertSeverity = ... 는 다음 호출의 shouldAlert 판단용.
   이 두 줄 없으면 cooldown이 영원히 작동 안 함 — 매번 첫 alert처럼 발사됨. */
void DeauthFloodDetector::processGlobalEvent(const ParsedFrame&  frame,
                                             TimePoint           now,
                                             TimePoint           cutoff,
                                             std::vector<Alert>& alerts) {
    globalEvents_.push_back(now);
    trimWindow(globalEvents_, cutoff);

    const int channelKey = frame.channel.value_or(-1);
    CooldownState& gcd = globalCooldowns_[channelKey];

    auto sev = severityFor(globalEvents_.size(), thresh_.global);
    if (!sev.has_value() || !shouldAlert(gcd, sev.value(), now)) return;

    alerts.push_back(Alert{
        sev.value(),
        now,
        frame.channel,
        DeauthFloodPayload{
            AlertScope::global,
            std::nullopt,             // source — global이므로 없음
            globalEvents_.size(),
            window_,
            0,                        // total — global은 의미 없음
            std::nullopt,             // reasonCode — global은 의미 없음
        },
    });
    gcd.lastAlert         = now;
    gcd.lastAlertSeverity = sev.value();
}

/* processPerSourceEvent — per-source 차원: frame.src별 윈도우/통계 갱신 + 해당 source cooldown 적용한 alert.

   processGlobalEvent와 평행 구조 — stats가 맵 안 값의 별칭이라 stats 수정 시
   맵 안 값 직접 변경됨. 끝부분 stats.cd.lastAlert 갱신 안 하면 cooldown 영원히 안 작동. */
void DeauthFloodDetector::processPerSourceEvent(const ParsedFrame&  frame,
                                                TimePoint           now,
                                                TimePoint           cutoff,
                                                std::vector<Alert>& alerts) {
    DeauthSourceStats& stats = sources_[frame.src];
    stats.recent.push_back(now);
    trimWindow(stats.recent, cutoff);
    stats.total++;
    stats.lastDeauthSeen = now;

    auto sev = severityFor(stats.recent.size(), thresh_.perSource);
    if (!sev.has_value() || !shouldAlert(stats.cd, sev.value(), now)) return;

    alerts.push_back(Alert{
        sev.value(),
        now,
        frame.channel,
        DeauthFloodPayload{
            AlertScope::perSource,
            frame.src,
            stats.recent.size(),
            window_,
            stats.total,
            frame.reasonCode,
        },
    });
    stats.cd.lastAlert         = now;
    stats.cd.lastAlertSeverity = sev.value();
}
