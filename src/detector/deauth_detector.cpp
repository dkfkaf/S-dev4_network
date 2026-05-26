/* deauth_detector.cpp — DeauthFloodDetector 구현 (IDetector::observe).
   들어온 deauth frame을 3차원(globalRate / perSrcMac / perBssid) 슬라이딩 윈도우에 누적,
   임계치 도달 시 cooldown+escalation 정책으로 Alert 발사.
   reason 3/8(정상 disconnect)는 perSrcMac/perBssid 카운터에서 제외. idle entry 5분 후 cleanup. */

#include "pch.h"
#include "deauth_detector.h"
#include "dot11.h"
#include <algorithm>

// reason 3(STA leaving deauth) / 8(STA leaving disassoc) — 핸드폰 toggle 같은 정상 disconnect.
// nullopt는 의심으로 간주 (공격자가 reason 안 보낼 수 있음).
bool DeauthFloodDetector::isNormalDisconnect(std::optional<uint16_t> reason) {
    if (!reason.has_value()) return false;
    return reason.value() == 3 || reason.value() == 8;
}

// srcMacStats_/bssidStats_가 동일 타입(map<Mac, DeauthEntryStats>)이라 일반 함수로 공통화.
// throttle: interval 안 지났으면 skip — 매 observe()마다 전체 스캔 방지.
void DeauthFloodDetector::forgetIdleEntries(std::map<Mac, DeauthEntryStats>& m,
                                            std::optional<TimePoint>&        lastRun,
                                            TimePoint                        now,
                                            std::chrono::milliseconds        interval,
                                            std::chrono::milliseconds        idleTimeout) {
    if (lastRun.has_value() && (now - lastRun.value()) < interval) return;
    lastRun = now;
    for (auto it = m.begin(); it != m.end(); ) {
        if (it->second.recent.empty() && (now - it->second.lastDeauthSeen) > idleTimeout) {
            it = m.erase(it);
        } else {
            ++it;
        }
    }
}

// perSrcMac/perBssid 둘 다 같은 4줄 업데이트 — 추출.
void DeauthFloodDetector::updateEntryStats(DeauthEntryStats& stats, TimePoint now, TimePoint cutoff) {
    stats.recent.push_back(now);
    trimWindow(stats.recent, cutoff);
    stats.total++;
    stats.lastDeauthSeen = now;
}

// alert 발사 후 cooldown 갱신 — global/perSrcMac/perBssid 셋 다 같은 2줄.
void DeauthFloodDetector::markAlertFired(CooldownState& state, TimePoint now, AlertSeverity severity) {
    state.lastAlert         = now;
    state.lastAlertSeverity = severity;
}

DeauthFloodDetector::DeauthFloodDetector(DeauthDetectorConfig config)
    : window_(config.window),
      thresh_(config.thresholds),
      cooldown_(config.cooldown),
      sourceIdleTimeout_(config.sourceIdleTimeout),
      removalInterval_(config.removalInterval) {}

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

namespace {
std::string formatTier(const char* name, const SeverityTier& t) {
    std::ostringstream oss;
    oss << "  " << name << " " << t.info << "/" << t.warn << "/" << t.critical;
    return oss.str();
}
}  // namespace

// 줄 단위 — indent/prefix는 caller가 결정. detector는 자기 데이터만 표현.
std::vector<std::string> DeauthFloodDetector::policyLines() const {
    const auto windowSec = std::chrono::duration_cast<std::chrono::seconds>(window_).count();
    const auto cooldownSec = std::chrono::duration_cast<std::chrono::seconds>(cooldown_).count();
    std::ostringstream firstLine;
    firstLine << "window=" << windowSec << "s, cooldown=" << cooldownSec << "s";

    return {
        firstLine.str(),
        "thresholds (info/warn/critical):",
        formatTier("globalRate", thresh_.globalRate),
        formatTier("perSrcMac ", thresh_.perSrcMac),
        formatTier("perBssid  ", thresh_.perBssid),
    };
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

    // idle entry cleanup은 항상 실행 — 정상 disconnect 기간에도 30초 throttle 내에서 만료.
    // globalEvents_도 같이 trim해야 정상 disconnect 기간에 stale entry 누적 안 됨.
    forgetIdleEntries(srcMacStats_, lastRemovalRun_,      now, removalInterval_, sourceIdleTimeout_);
    forgetIdleEntries(bssidStats_,  lastBssidRemovalRun_, now, removalInterval_, sourceIdleTimeout_);
    trimWindow(globalEvents_, now - window_);

    // reason 3/8(정상 disconnect)은 카운터 누적 + alert 전부 skip. trade-off: 공격자가 reason=3/8로
    // 위장하면 미탐 — 단, 시중 도구 대부분 reason=7 사용해서 실용 우회는 거의 없음.
    if (isNormalDisconnect(frame.reasonCode)) return {};

    const TimePoint cutoff = now - window_;

    processGlobalEvent  (frame, now,         alerts);   // global은 cutoff 안 씀
    processPerSrcMacEvent(frame, now, cutoff, alerts);
    processPerBssidEvent (frame, now, cutoff, alerts);

    return alerts;
}


// 전역 raw rate 누적 + 단일 cooldown (채널별 세분은 perBssid가 담당).
// trim은 observe()가 이미 했으므로 여기선 push만.
void DeauthFloodDetector::processGlobalEvent(const ParsedFrame&  frame,
                                             TimePoint           now,
                                             std::vector<Alert>& alerts) {
    globalEvents_.push_back(now);

    auto severity = severityFor(globalEvents_.size(), thresh_.globalRate);
    if (!severity.has_value() || !shouldAlert(globalCooldown_, severity.value(), now)) return;

    alerts.push_back(Alert{
        severity.value(),
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
    markAlertFired(globalCooldown_, now, severity.value());
}

// 송신자(addr2) MAC별 누적. stats는 map 값의 참조 — stats.state 갱신이 곧 srcMacStats_[src].state 갱신.
void DeauthFloodDetector::processPerSrcMacEvent(const ParsedFrame&  frame,
                                                TimePoint           now,
                                                TimePoint           cutoff,
                                                std::vector<Alert>& alerts) {
    DeauthSrcMacStats& stats = srcMacStats_[frame.src];
    updateEntryStats(stats, now, cutoff);

    auto severity = severityFor(stats.recent.size(), thresh_.perSrcMac);
    if (!severity.has_value() || !shouldAlert(stats.state, severity.value(), now)) return;

    alerts.push_back(Alert{
        severity.value(),
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
    markAlertFired(stats.state, now, severity.value());
}

// 표적 BSSID별 누적 — MAC randomization 우회 (attacker가 src를 바꿔도 표적은 고정).
void DeauthFloodDetector::processPerBssidEvent(const ParsedFrame&  frame,
                                               TimePoint           now,
                                               TimePoint           cutoff,
                                               std::vector<Alert>& alerts) {
    DeauthBssidStats& stats = bssidStats_[frame.bssid];
    updateEntryStats(stats, now, cutoff);

    auto severity = severityFor(stats.recent.size(), thresh_.perBssid);
    if (!severity.has_value() || !shouldAlert(stats.state, severity.value(), now)) return;

    alerts.push_back(Alert{
        severity.value(),
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
    markAlertFired(stats.state, now, severity.value());
}

