#include "pch.h"
#include "deauth_detector.h"
#include "mgmt_parser.h"
#include <algorithm>
#include <sstream>

DeauthEvent DeauthEvent::from(const ParsedFrame& f) {
    return {std::chrono::steady_clock::now(),
            f.src, f.dst, f.bssid, f.rssi, f.reasonCode, f.channel};
}

// observe() / 조회 메서드는 모두 mtx_ 락. private helper는 caller가 락 잡은 상태에서만 호출.

DeauthFloodDetector::DeauthFloodDetector(std::chrono::milliseconds window,
                                         DeauthThresholds          thresh,
                                         std::chrono::milliseconds cooldown,
                                         std::chrono::milliseconds idleEvictAfter)
    : window_(window),
      thresh_(thresh),
      cooldown_(cooldown),
      idleEvictAfter_(idleEvictAfter) {}

void DeauthFloodDetector::prune(Window& q, TimePoint cutoff) {
    while (!q.empty() && q.front() < cutoff) q.pop_front();
}

std::optional<AlertSeverity> DeauthFloodDetector::severityFor(size_t count,
                                                              size_t infoTh,
                                                              size_t warnTh,
                                                              size_t critTh) {
    if (count >= critTh) return AlertSeverity::critical;
    if (count >= warnTh) return AlertSeverity::warn;
    if (count >= infoTh) return AlertSeverity::info;
    return std::nullopt;
}

// invariant: lastAlertTime이 set이면 lastSev도 set (호출 측에서 동시 갱신).
bool DeauthFloodDetector::shouldFire(std::optional<AlertSeverity>    lastSev,
                                     AlertSeverity                   currentSev,
                                     const std::optional<TimePoint>& lastAlertTime,
                                     TimePoint                       now) const {
    if (!lastAlertTime.has_value()) return true;
    if (currentSev > lastSev.value()) return true;
    return (now - lastAlertTime.value()) >= cooldown_;
}

void DeauthFloodDetector::evictIdleSources(TimePoint now) {
    // throttle: 매 observe()마다 전체 맵 스캔 회피
    if (lastEvictionRun_.has_value() &&
        (now - lastEvictionRun_.value()) < evictionInterval_) return;
    lastEvictionRun_ = now;

    for (auto it = sources_.begin(); it != sources_.end(); ) {
        const auto& s = it->second;
        if (s.recent.empty() && (now - s.lastSeen) > idleEvictAfter_) {
            it = sources_.erase(it);
        } else {
            ++it;
        }
    }
}

size_t DeauthFloodDetector::globalCount() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return globalEvents_.size();
}

size_t DeauthFloodDetector::trackedSources() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return sources_.size();
}

std::optional<DeauthSourceStats> DeauthFloodDetector::statsFor(const Mac& src) const {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = sources_.find(src);
    if (it == sources_.end()) return std::nullopt;
    return it->second;
}

std::vector<Alert> DeauthFloodDetector::observe(const DeauthEvent& ev) {
    std::lock_guard<std::mutex> lock(mtx_);
    std::vector<Alert> alerts;

    // 역전된 ts는 직전 최대값으로 clamp → deque 단조성 유지 (prune 정확성).
    const TimePoint now = globalEvents_.empty()
        ? ev.ts
        : std::max(ev.ts, globalEvents_.back());
    const TimePoint cutoff = now - window_;

    globalEvents_.push_back(now);
    prune(globalEvents_, cutoff);

    // 전역 alert — cooldown은 채널별로 분리
    const int channelKey = ev.channel.value_or(-1);
    CooldownState& gcd = globalCooldowns_[channelKey];

    if (auto sev = severityFor(globalEvents_.size(),
                               thresh_.globalInfo,
                               thresh_.globalWarn,
                               thresh_.globalCritical);
        sev.has_value() && shouldFire(gcd.lastAlertSeverity, sev.value(),
                                      gcd.lastAlert, now))
    {
        // count는 모든 채널 합산 → "(latest: ch=X)"로 표기. "global (ch=11): 50"은 오해 유발.
        std::ostringstream oss;
        oss << "global deauth flood: " << globalEvents_.size()
            << " events in last " << window_.count() << "ms";
        if (ev.channel.has_value()) oss << " (latest: ch=" << *ev.channel << ")";
        alerts.push_back(Alert{sev.value(), oss.str(), now, std::nullopt, globalEvents_.size()});
        gcd.lastAlert         = now;
        gcd.lastAlertSeverity = sev.value();
    }

    DeauthSourceStats& s = sources_[ev.src];
    s.recent.push_back(now);
    prune(s.recent, cutoff);
    s.total++;
    s.lastSeen = now;

    if (auto sev = severityFor(s.recent.size(),
                               thresh_.perSourceInfo,
                               thresh_.perSourceWarn,
                               thresh_.perSourceCritical);
        sev.has_value() && shouldFire(s.lastAlertSeverity, sev.value(),
                                      s.lastAlert, now))
    {
        // 전역과 통일된 포맷: 'latest: ch=X'로 'trigger한 마지막 이벤트의 채널'임을 명시.
        std::ostringstream oss;
        oss << "deauth from " << ev.src.toString()
            << ": " << s.recent.size() << " events in last "
            << window_.count() << "ms (total=" << s.total;
        if (ev.channel.has_value())    oss << ", latest: ch=" << *ev.channel;
        if (ev.reasonCode.has_value()) oss << ", reason=" << *ev.reasonCode;
        oss << ")";
        alerts.push_back(Alert{sev.value(), oss.str(), now, ev.src, s.recent.size()});
        s.lastAlert         = now;
        s.lastAlertSeverity = sev.value();
    }

    evictIdleSources(now);
    return alerts;
}
