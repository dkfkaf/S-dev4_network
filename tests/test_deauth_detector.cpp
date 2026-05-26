#include <gtest/gtest.h>

#include <chrono>
#include <optional>
#include <variant>
#include <vector>

#include "alert.h"
#include "deauth_detector.h"
#include "mgmt_parser.h"
#include "dot11.h"
#include "mac.h"

using namespace std::chrono_literals;
using clock_type = std::chrono::steady_clock;

namespace {

ParsedFrame mkDeauthFrame(const Mac& src,
                          std::optional<int>      channel = 6,
                          std::optional<Mac>      bssid   = std::nullopt,
                          std::optional<uint16_t> reason  = std::nullopt) {
    ParsedFrame f{};
    f.frameType  = MGMT_SUBTYPE_DEAUTH;
    f.src        = src;
    f.channel    = channel;
    if (bssid.has_value()) f.bssid = bssid.value();
    f.reasonCode = reason;
    return f;
}

ParsedFrame mkBeaconFrame() {
    ParsedFrame f{};
    f.frameType = MGMT_SUBTYPE_BEACON;
    return f;
}

Mac macOf(const std::string& s) {
    return Mac::fromString(s).value();
}

// alerts에서 (scope, severity) 매칭 개수 — DeauthFloodPayload만 본다.
int countDeauthAlerts(const std::vector<Alert>& alerts,
                      AlertScope     scope,
                      AlertSeverity  severity) {
    int n = 0;
    for (const auto& a : alerts) {
        if (a.severity != severity) continue;
        if (!std::holds_alternative<DeauthFloodPayload>(a.payload)) continue;
        const auto& p = std::get<DeauthFloodPayload>(a.payload);
        if (p.scope == scope) ++n;
    }
    return n;
}

}  // namespace

// ─────────────────────────────────────────────────────────────────────────────
// severityFor — tier 경계값
// ─────────────────────────────────────────────────────────────────────────────
TEST(SeverityFor, BelowInfoReturnsNullopt) {
    SeverityTier tier{5, 10, 20};
    EXPECT_FALSE(DeauthFloodDetector::severityFor(0, tier).has_value());
    EXPECT_FALSE(DeauthFloodDetector::severityFor(4, tier).has_value());
}

TEST(SeverityFor, AtAndAboveBoundaries) {
    SeverityTier tier{5, 10, 20};
    EXPECT_EQ(DeauthFloodDetector::severityFor(5,   tier).value(), AlertSeverity::info);
    EXPECT_EQ(DeauthFloodDetector::severityFor(9,   tier).value(), AlertSeverity::info);
    EXPECT_EQ(DeauthFloodDetector::severityFor(10,  tier).value(), AlertSeverity::warn);
    EXPECT_EQ(DeauthFloodDetector::severityFor(19,  tier).value(), AlertSeverity::warn);
    EXPECT_EQ(DeauthFloodDetector::severityFor(20,  tier).value(), AlertSeverity::critical);
    EXPECT_EQ(DeauthFloodDetector::severityFor(999, tier).value(), AlertSeverity::critical);
}

// ─────────────────────────────────────────────────────────────────────────────
// trimWindow — 빈 큐 / 부분 trim / 경계
// ─────────────────────────────────────────────────────────────────────────────
TEST(TrimWindow, EmptyQueueIsNoOp) {
    Window q;
    DeauthFloodDetector::trimWindow(q, clock_type::now());
    EXPECT_EQ(q.size(), 0u);
}

TEST(TrimWindow, DropsEntriesStrictlyOlderThanCutoff) {
    Window q;
    const auto base = clock_type::now();
    q.push_back(base);
    q.push_back(base + 2s);
    q.push_back(base + 4s);
    q.push_back(base + 6s);

    DeauthFloodDetector::trimWindow(q, base + 3s);

    ASSERT_EQ(q.size(), 2u);
    EXPECT_EQ(q.front(), base + 4s);
    EXPECT_EQ(q.back(),  base + 6s);
}

TEST(TrimWindow, EntryEqualToCutoffIsKept) {
    Window q;
    const auto base = clock_type::now();
    q.push_back(base + 5s);

    DeauthFloodDetector::trimWindow(q, base + 5s);  // entry == cutoff, "< cutoff"가 false

    EXPECT_EQ(q.size(), 1u);
}

// ─────────────────────────────────────────────────────────────────────────────
// observe — 통합 동작
// ─────────────────────────────────────────────────────────────────────────────
TEST(Observe, NonDeauthFrameProducesNoAlerts) {
    DeauthFloodDetector det;
    auto alerts = det.observe(clock_type::now(), mkBeaconFrame());
    EXPECT_TRUE(alerts.empty());
    EXPECT_EQ(det.globalCount(), 0u);
}

TEST(Observe, AlertCarriesDeauthFloodPayload) {
    DeauthThresholds thresh;
    thresh.globalRate    = {2, 100, 1000};   // 2번째 deauth에서 global info
    thresh.perSrcMac = {99, 100, 101};   // per-source는 이 테스트에서 사실상 비활성
    DeauthFloodDetector det(DeauthDetectorConfig{10s, thresh, 5s});

    const Mac attacker = macOf("AA:BB:CC:DD:EE:01");
    const auto t0 = clock_type::now();

    det.observe(t0,           mkDeauthFrame(attacker));
    auto alerts = det.observe(t0 + 100ms, mkDeauthFrame(attacker));

    ASSERT_FALSE(alerts.empty());
    EXPECT_TRUE(std::holds_alternative<DeauthFloodPayload>(alerts[0].payload));
    EXPECT_STREQ(categoryName(alerts[0].payload), "deauth_flood");
}

TEST(Observe, CooldownSuppressesRepeatedSameSeverity) {
    DeauthThresholds thresh;
    thresh.globalRate    = {3, 100, 1000};      // 3개에서 info
    thresh.perSrcMac = {999, 1000, 1001};   // perSrcMac 잠재 발사 방지
    const auto cooldown = 5s;
    DeauthFloodDetector det(DeauthDetectorConfig{10s, thresh, cooldown});

    const Mac attacker = macOf("AA:BB:CC:DD:EE:01");
    const auto t0 = clock_type::now();

    det.observe(t0,           mkDeauthFrame(attacker));
    det.observe(t0 + 100ms,   mkDeauthFrame(attacker));
    auto firstFire = det.observe(t0 + 200ms, mkDeauthFrame(attacker));
    EXPECT_EQ(countDeauthAlerts(firstFire, AlertScope::globalRate, AlertSeverity::info), 1);

    // 같은 severity가 cooldown 안에 다시 임계 충족 — 억제되어야 함
    auto suppressed = det.observe(t0 + 500ms, mkDeauthFrame(attacker));
    EXPECT_EQ(countDeauthAlerts(suppressed, AlertScope::globalRate, AlertSeverity::info), 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// 정교화: reason code 필터, per-BSSID 카운터
// ─────────────────────────────────────────────────────────────────────────────
TEST(Observe, NormalDisconnectReasonFullyExcludedFromAllScopes) {
    DeauthThresholds thresh;
    thresh.globalRate = {3, 100, 1000};       // 3개에서 globalRate info — 그런데 정상 disconnect라 트리거 안 돼야 함
    thresh.perSrcMac  = {3, 100, 1000};
    thresh.perBssid   = {3, 100, 1000};
    DeauthFloodDetector det(DeauthDetectorConfig{10s, thresh, 5s});

    const Mac attacker = macOf("AA:BB:CC:DD:EE:01");
    const Mac target   = macOf("00:11:22:33:44:55");
    const auto t0 = clock_type::now();

    // reason=3 (STA leaving, 정상 disconnect) — global/perSrcMac/perBssid 모두에서 완전 제외
    det.observe(t0,         mkDeauthFrame(attacker, 6, target, 3));
    det.observe(t0 + 50ms,  mkDeauthFrame(attacker, 6, target, 3));
    auto alerts = det.observe(t0 + 100ms, mkDeauthFrame(attacker, 6, target, 3));

    // 어떤 scope에서도 alert 없어야 함 — 카운터에 누적조차 안 됨
    EXPECT_TRUE(alerts.empty());
    EXPECT_EQ(det.globalCount(), 0u);
    EXPECT_EQ(det.trackedSrcMacs(), 0u);
    EXPECT_EQ(det.trackedBssids(), 0u);
}

TEST(Observe, SuspiciousReasonCountsTowardsPerSource) {
    DeauthThresholds thresh;
    thresh.globalRate    = {1000, 2000, 3000};
    thresh.perSrcMac = {3, 100, 1000};
    thresh.perBssid  = {1000, 2000, 3000};
    DeauthFloodDetector det(DeauthDetectorConfig{10s, thresh, 5s});

    const Mac attacker = macOf("AA:BB:CC:DD:EE:01");
    const Mac target   = macOf("00:11:22:33:44:55");
    const auto t0 = clock_type::now();

    // reason=7 (class 3 frame from non-associated STA — aireplay-ng 기본값)
    det.observe(t0,         mkDeauthFrame(attacker, 6, target, 7));
    det.observe(t0 + 50ms,  mkDeauthFrame(attacker, 6, target, 7));
    auto alerts = det.observe(t0 + 100ms, mkDeauthFrame(attacker, 6, target, 7));

    EXPECT_EQ(countDeauthAlerts(alerts, AlertScope::perSrcMac, AlertSeverity::info), 1);
}

TEST(Observe, PerBssidAlertCatchesMacRandomizedAttack) {
    DeauthThresholds thresh;
    thresh.globalRate    = {1000, 2000, 3000};
    thresh.perSrcMac = {1000, 2000, 3000};   // per-source는 트리거 안 되게
    thresh.perBssid  = {3, 100, 1000};        // 3개에서 info
    DeauthFloodDetector det(DeauthDetectorConfig{10s, thresh, 5s});

    const Mac target = macOf("00:11:22:33:44:55");
    const auto t0 = clock_type::now();

    // MAC randomization 공격자 시뮬레이션 — 매번 다른 src, 같은 target BSSID
    det.observe(t0,         mkDeauthFrame(macOf("AA:00:00:00:00:01"), 6, target, 7));
    det.observe(t0 + 50ms,  mkDeauthFrame(macOf("AA:00:00:00:00:02"), 6, target, 7));
    auto alerts = det.observe(t0 + 100ms, mkDeauthFrame(macOf("AA:00:00:00:00:03"), 6, target, 7));

    // per-source는 src가 모두 달라서 누적 안 됨. per-BSSID가 잡아냄 — 이게 핵심 가치.
    EXPECT_EQ(countDeauthAlerts(alerts, AlertScope::perSrcMac, AlertSeverity::info), 0);
    EXPECT_EQ(countDeauthAlerts(alerts, AlertScope::perBssid,  AlertSeverity::info), 1);
}

TEST(Observe, EscalationBypassesCooldown) {
    DeauthThresholds thresh;
    thresh.globalRate    = {3, 5, 100};          // info=3, warn=5 — escalation 가능
    thresh.perSrcMac = {999, 1000, 1001};
    DeauthFloodDetector det(DeauthDetectorConfig{10s, thresh, 5s});

    const Mac attacker = macOf("AA:BB:CC:DD:EE:01");
    const auto t0 = clock_type::now();

    // 3개 → global info 발사
    det.observe(t0,           mkDeauthFrame(attacker));
    det.observe(t0 + 50ms,    mkDeauthFrame(attacker));
    auto fireInfo = det.observe(t0 + 100ms, mkDeauthFrame(attacker));
    EXPECT_EQ(countDeauthAlerts(fireInfo, AlertScope::globalRate, AlertSeverity::info), 1);

    // 4, 5번째 — count=5에서 warn. 직전 alert로부터 0.3초 → cooldown 안. 그러나 escalation이라 발사.
    det.observe(t0 + 200ms, mkDeauthFrame(attacker));
    auto fireWarn = det.observe(t0 + 300ms, mkDeauthFrame(attacker));
    EXPECT_EQ(countDeauthAlerts(fireWarn, AlertScope::globalRate, AlertSeverity::warn), 1);
}
