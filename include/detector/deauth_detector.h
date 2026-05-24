#pragma once
#include <chrono>
#include <deque>
#include <map>
#include <mutex>
#include <optional>
#include <vector>
#include "alert.h"
#include "mac.h"

using Window = std::deque<TimePoint>;

struct DeauthEvent {
    TimePoint                ts;
    Mac                      src;
    Mac                      dst;
    Mac                      bssid;
    std::optional<int8_t>    rssi;
    std::optional<uint16_t>  reasonCode;
    std::optional<int>       channel;
};

struct CooldownState {
    std::optional<TimePoint>     lastAlert;
    std::optional<AlertSeverity> lastAlertSeverity;
};

/*애는 더 공부하기*/
struct DeauthSourceStats {
    Window         recent;
    uint64_t       total = 0;
    TimePoint      lastSeen;
    CooldownState  cd;
};

struct SeverityTier {
    size_t info;
    size_t warn;
    size_t critical;
};

struct DeauthThresholds {
    SeverityTier global    = {10, 20, 40};
    SeverityTier perSource = {5, 10, 20};
};

class DeauthFloodDetector {
public:
    DeauthFloodDetector(std::chrono::milliseconds window            = std::chrono::seconds(10),
                        DeauthThresholds          thresh            = {},
                        std::chrono::milliseconds cooldown          = std::chrono::seconds(3),
                        std::chrono::milliseconds sourceIdleTimeout = std::chrono::minutes(5));

    /*애도 공부하기*/
    std::vector<Alert> observe(const DeauthEvent& event);

    size_t globalCount() const;
    size_t trackedSources() const;
    std::optional<DeauthSourceStats> statsFor(const Mac& src) const;

private:
    static void trimWindow(Window& q, TimePoint cutoff);
    static std::optional<AlertSeverity> severityFor(size_t count, const SeverityTier& tier);

    bool shouldAlert(const CooldownState& cd, AlertSeverity currentSev, TimePoint now) const;

    void processGlobalEvent(const DeauthEvent& event, TimePoint now, TimePoint cutoff,
                            std::vector<Alert>& alerts);
    void processPerSourceEvent(const DeauthEvent& event, TimePoint now, TimePoint cutoff,
                               std::vector<Alert>& alerts);

    void forgetIdleSources(TimePoint now);

    std::chrono::milliseconds  window_;
    DeauthThresholds           thresh_;
    std::chrono::milliseconds  cooldown_;
    std::chrono::milliseconds  sourceIdleTimeout_;
    std::chrono::milliseconds  removalInterval_{std::chrono::seconds(30)};

    mutable std::mutex                                mtx_;

    Window                                            globalEvents_;
    std::map<int, CooldownState>                      globalCooldowns_;
    std::map<Mac, DeauthSourceStats>                  sources_;
    std::optional<TimePoint>                          lastRemovalRun_;
};
