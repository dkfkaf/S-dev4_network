#include "pch.h"
#include "deauth_detector.h"
#include <algorithm>

DeauthFloodDetector::DeauthFloodDetector(std::chrono::milliseconds window,
                                         DeauthThresholds          thresh,
                                         std::chrono::milliseconds cooldown,
                                         std::chrono::milliseconds sourceIdleTimeout)
    : window_(window),
      thresh_(thresh),
      cooldown_(cooldown),
      sourceIdleTimeout_(sourceIdleTimeout) {}

      /*애는 다시 볼것*/
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

bool DeauthFloodDetector::shouldAlert(const CooldownState& cd,
                                      AlertSeverity        currentSev,
                                      TimePoint            now) const {
    if (!cd.lastAlert.has_value()) return true;
    if (currentSev > cd.lastAlertSeverity.value()) return true;
    return (now - cd.lastAlert.value()) >= cooldown_;
}

/*애도 공부하기*/
void DeauthFloodDetector::forgetIdleSources(TimePoint now) {
    if (lastRemovalRun_.has_value() &&
        (now - lastRemovalRun_.value()) < removalInterval_) return;
    lastRemovalRun_ = now;

    for (auto it = sources_.begin(); it != sources_.end(); ) {
        const auto& stats = it->second;
        if (stats.recent.empty() && (now - stats.lastSeen) > sourceIdleTimeout_) {
            it = sources_.erase(it);
        } else {
            ++it;
        }
    }
}
/*뮤텍스를 왜 걸었지*/

size_t DeauthFloodDetector::globalCount() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return globalEvents_.size();
}

size_t DeauthFloodDetector::trackedSources() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return sources_.size();
}

/*애도 어렵다*/
std::optional<DeauthSourceStats> DeauthFloodDetector::statsFor(const Mac& src) const {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = sources_.find(src);
    if (it == sources_.end()) return std::nullopt;
    return it->second;
}

/*어려웡 ㅎ*/
std::vector<Alert> DeauthFloodDetector::observe(const DeauthEvent& event) {
    std::lock_guard<std::mutex> lock(mtx_);
    std::vector<Alert> alerts;

    const TimePoint now = globalEvents_.empty()
        ? event.ts
        : std::max(event.ts, globalEvents_.back());
    const TimePoint cutoff = now - window_;

    processGlobalEvent(event, now, cutoff, alerts);
    processPerSourceEvent(event, now, cutoff, alerts);
    forgetIdleSources(now);

    return alerts;
}

void DeauthFloodDetector::processGlobalEvent(const DeauthEvent& event,
                                             TimePoint           now,
                                             TimePoint           cutoff,
                                             std::vector<Alert>& alerts) {
    globalEvents_.push_back(now);
    trimWindow(globalEvents_, cutoff);

    const int channelKey = event.channel.value_or(-1);
    CooldownState& gcd = globalCooldowns_[channelKey];

    auto sev = severityFor(globalEvents_.size(), thresh_.global);
    if (!sev.has_value() || !shouldAlert(gcd, sev.value(), now)) return;

    alerts.push_back(Alert{
        sev.value(),
        AlertScope::global,
        now,
        std::nullopt,
        globalEvents_.size(),
        window_,
        event.channel,
        std::nullopt,
        0,
    });
    gcd.lastAlert         = now;
    gcd.lastAlertSeverity = sev.value();
}

void DeauthFloodDetector::processPerSourceEvent(const DeauthEvent& event,
                                                TimePoint           now,
                                                TimePoint           cutoff,
                                                std::vector<Alert>& alerts) {
    DeauthSourceStats& stats = sources_[event.src];
    stats.recent.push_back(now);
    trimWindow(stats.recent, cutoff);
    stats.total++;
    stats.lastSeen = now;

    auto sev = severityFor(stats.recent.size(), thresh_.perSource);
    if (!sev.has_value() || !shouldAlert(stats.cd, sev.value(), now)) return;

    alerts.push_back(Alert{
        sev.value(),
        AlertScope::perSource,
        now,
        event.src,
        stats.recent.size(),
        window_,
        event.channel,
        event.reasonCode,
        stats.total,
    });
    stats.cd.lastAlert         = now;
    stats.cd.lastAlertSeverity = sev.value();
}
