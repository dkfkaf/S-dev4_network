/* deauth_detector.cpp — DeauthFloodDetector 구현 (IDetector::observe).
   들어온 deauth frame을 3차원(globalRate / perSrcMac / perBssid) 슬라이딩 윈도우에 누적,
   임계치 도달 시 cooldown+escalation 정책으로 Alert 발사.
   reason 3/8(정상 disconnect)는 perSrcMac/perBssid 카운터에서 제외. idle entry 5분 후 cleanup. */

#include "pch.h"
#include "deauth_detector.h"
#include "dot11.h"
#include <algorithm>
#include <sstream>

namespace {

// reason 3(STA leaving deauth) / 8(STA leaving disassoc) — 핸드폰 toggle 같은 정상 disconnect.
// nullopt는 의심으로 간주 (공격자가 reason 안 보낼 수 있음).
bool isNormalDisconnect(std::optional<uint16_t> reason) {
    if (!reason.has_value()) return false;
    return reason.value() == 3 || reason.value() == 8;
}

}  // namespace

DeauthFloodDetector::DeauthFloodDetector(std::chrono::milliseconds window,
                                         DeauthThresholds          thresh,
                                         std::chrono::milliseconds cooldown,
                                         std::chrono::milliseconds sourceIdleTimeout,
                                         std::chrono::milliseconds removalInterval)
    : window_(window),
      thresh_(thresh),
      cooldown_(cooldown),
      sourceIdleTimeout_(sourceIdleTimeout),
      removalInterval_(removalInterval) {}

// deque의 시간 순 정렬 가정 활용 — front가 cutoff보다 옛날이면 pop, 아니면 뒤는 다 윈도우 안 (amortized O(1)).
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

// 첫 alert → 발사. escalation(severity 상승) → cooldown 무시 발사. 같은/낮은 severity → cooldown 적용.
bool DeauthFloodDetector::shouldAlert(const CooldownState& state,
                                      AlertSeverity        currentSeverity,
                                      TimePoint            now) const {
    if (!state.lastAlert.has_value()) return true;
    if (currentSeverity > state.lastAlertSeverity.value()) return true;
    return (now - state.lastAlert.value()) >= cooldown_;
}

// 아래 const 조회 메서드들이 mutex_를 잡으므로 mutex_는 mutable.
std::string DeauthFloodDetector::policySummary() const {
    const auto windowSec = std::chrono::duration_cast<std::chrono::seconds>(window_).count();
    const auto cooldownSec = std::chrono::duration_cast<std::chrono::seconds>(cooldown_).count();
    const auto& g = thresh_.globalRate;
    const auto& s = thresh_.perSrcMac;
    const auto& b = thresh_.perBssid;
    std::ostringstream oss;
    oss << "window=" << windowSec << "s, cooldown=" << cooldownSec << "s, "
        << "thresholds(info/warn/critical): "
        << "globalRate=" << g.info << "/" << g.warn << "/" << g.critical << ", "
        << "perSrcMac="  << s.info << "/" << s.warn << "/" << s.critical << ", "
        << "perBssid="   << b.info << "/" << b.warn << "/" << b.critical;
    return oss.str();
}

size_t DeauthFloodDetector::globalCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return globalEvents_.size();
}

size_t DeauthFloodDetector::trackedSrcMacs() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return srcMacStats_.size();
}

size_t DeauthFloodDetector::trackedBssids() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return bssidStats_.size();
}

std::optional<DeauthBssidStats> DeauthFloodDetector::bssidStatsFor(const Mac& bssid) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = bssidStats_.find(bssid);
    if (it == bssidStats_.end()) return std::nullopt;
    return it->second;
}

std::optional<DeauthSrcMacStats> DeauthFloodDetector::statsFor(const Mac& src) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = srcMacStats_.find(src);
    if (it == srcMacStats_.end()) return std::nullopt;
    return it->second;
}

/* IDetector 진입점. timestamp는 max(timestamp, 큐 마지막)로 clamp — 듀얼 캡처 스레드 간 시간 역전 방지
   (정렬 깨지면 trimWindow가 잘못 동작). */
std::vector<Alert> DeauthFloodDetector::observe(TimePoint timestamp, const ParsedFrame& frame) {
    if (frame.frameType != MGMT_SUBTYPE_DEAUTH) return {};

    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Alert> alerts;

    const TimePoint now = globalEvents_.empty()
        ? timestamp
        : std::max(timestamp, globalEvents_.back());
    const TimePoint cutoff = now - window_;

    processGlobalEvent(frame, now, cutoff, alerts);   // global은 항상 누적 (raw rate, broadcast 백스톱)

    // 정상 disconnect(reason 3/8)는 perSrcMac/perBssid 카운터 제외 — 핸드폰 toggle false positive 방지
    if (!isNormalDisconnect(frame.reasonCode)) {
        processPerSrcMacEvent(frame, now, cutoff, alerts);
        processPerBssidEvent (frame, now, cutoff, alerts);
    }

    forgetIdleSrcMacs(now);
    forgetIdleBssids(now);

    return alerts;
}

// idle src 제거 (메모리 관리). throttle: removalInterval 안 지났으면 skip.
void DeauthFloodDetector::forgetIdleSrcMacs(TimePoint now) {
    if (lastRemovalRun_.has_value() && (now - lastRemovalRun_.value()) < removalInterval_) return;
    lastRemovalRun_ = now;
    for (auto it = srcMacStats_.begin(); it != srcMacStats_.end(); ) {
        if (it->second.recent.empty() && (now - it->second.lastDeauthSeen) > sourceIdleTimeout_) {
            it = srcMacStats_.erase(it);
        } else {
            ++it;
        }
    }
}

// idle bssid 제거. forgetIdleSrcMacs와 같은 패턴, 다른 맵/타이머.
void DeauthFloodDetector::forgetIdleBssids(TimePoint now) {
    if (lastBssidRemovalRun_.has_value() && (now - lastBssidRemovalRun_.value()) < removalInterval_) return;
    lastBssidRemovalRun_ = now;
    for (auto it = bssidStats_.begin(); it != bssidStats_.end(); ) {
        if (it->second.recent.empty() && (now - it->second.lastDeauthSeen) > sourceIdleTimeout_) {
            it = bssidStats_.erase(it);
        } else {
            ++it;
        }
    }
}

// 전역 raw rate 누적 + 단일 cooldown (채널별 세분은 perBssid가 담당).
void DeauthFloodDetector::processGlobalEvent(const ParsedFrame&  frame,
                                             TimePoint           now,
                                             TimePoint           cutoff,
                                             std::vector<Alert>& alerts) {
    globalEvents_.push_back(now);
    trimWindow(globalEvents_, cutoff);

    auto severity = severityFor(globalEvents_.size(), thresh_.globalRate);
    if (!severity.has_value() || !shouldAlert(globalCooldown_, severity.value(), now)) return;

    alerts.push_back(Alert{
        severity.value(),
        now,
        frame.channel,
        DeauthFloodPayload{
            AlertScope::globalRate,
            std::nullopt, std::nullopt, std::nullopt,  // srcMac/bssid/rssi — 다수 합산이라 의미 없음
            globalEvents_.size(),
            window_,
            0,
            std::nullopt,
        },
    });
    globalCooldown_.lastAlert         = now;
    globalCooldown_.lastAlertSeverity = severity.value();
}

// 송신자(addr2) MAC별 누적. stats는 map 값의 참조 — stats.state 갱신이 곧 srcMacStats_[src].state 갱신.
void DeauthFloodDetector::processPerSrcMacEvent(const ParsedFrame&  frame,
                                                TimePoint           now,
                                                TimePoint           cutoff,
                                                std::vector<Alert>& alerts) {
    DeauthSrcMacStats& stats = srcMacStats_[frame.src];
    stats.recent.push_back(now);
    trimWindow(stats.recent, cutoff);
    stats.total++;
    stats.lastDeauthSeen = now;

    auto severity = severityFor(stats.recent.size(), thresh_.perSrcMac);
    if (!severity.has_value() || !shouldAlert(stats.state, severity.value(), now)) return;

    alerts.push_back(Alert{
        severity.value(),
        now,
        frame.channel,
        DeauthFloodPayload{
            AlertScope::perSrcMac,
            frame.src,
            frame.bssid,
            frame.rssi,
            stats.recent.size(),
            window_,
            stats.total,
            frame.reasonCode,
        },
    });
    stats.state.lastAlert         = now;
    stats.state.lastAlertSeverity = severity.value();
}

// 표적 BSSID별 누적 — MAC randomization 우회 (attacker가 src를 바꿔도 표적은 고정).
void DeauthFloodDetector::processPerBssidEvent(const ParsedFrame&  frame,
                                               TimePoint           now,
                                               TimePoint           cutoff,
                                               std::vector<Alert>& alerts) {
    DeauthBssidStats& stats = bssidStats_[frame.bssid];
    stats.recent.push_back(now);
    trimWindow(stats.recent, cutoff);
    stats.total++;
    stats.lastDeauthSeen = now;

    auto severity = severityFor(stats.recent.size(), thresh_.perBssid);
    if (!severity.has_value() || !shouldAlert(stats.state, severity.value(), now)) return;

    alerts.push_back(Alert{
        severity.value(),
        now,
        frame.channel,
        DeauthFloodPayload{
            AlertScope::perBssid,
            std::nullopt,             // srcMac — MAC randomization으로 여러 송신자 가능
            frame.bssid,
            frame.rssi,
            stats.recent.size(),
            window_,
            stats.total,
            frame.reasonCode,
        },
    });
    stats.state.lastAlert         = now;
    stats.state.lastAlertSeverity = severity.value();
}

