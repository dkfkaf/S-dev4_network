# DeauthFloodDetector 코드 설명

`include/detector/deauth_detector.h` + `src/detector/deauth_detector.cpp` 의 동작과 설계를 풀어 쓴 문서.

---

## 1. 이 모듈은 무엇을 하나

802.11 Deauthentication 프레임의 **흐름을 시간 차원에서 추적**하여,
**짧은 시간 안에 비정상적으로 많이** 발생하면 알람을 생성하는 모듈.

### 왜 필요한가
Deauthentication 프레임은 정상 동작의 일부이기도 합니다 (AP가 client 연결 끊을 때).
하지만 공격자는 deauth를 **무더기로 쏘아서** 합법 client를 강제 disconnect시킬 수 있습니다 — 이게 **Deauth Flood 공격**입니다. 대표적인 도구:
- `aireplay-ng -0 N` : reason code 7로 N회 전송
- `mdk3 d` : 무차별 deauth

**단발성 deauth는 정상, 단시간에 다발이면 공격** — 이 차이를 알아내려면 "최근 N초 동안 몇 번 왔는지"를 세야 합니다. 이게 sliding window 패턴.

### 사용 위치
`main.cpp`에서 패킷 파싱 후 Deauth 프레임이면 detector에 전달:
```cpp
if (f.frameType == MGMT_SUBTYPE_DEAUTH) {
    // detector.observe()는 내부 mutex로 thread-safe
    for (const auto& a : detector.observe(make_deauth_event(f))) print_alert(a);
}
```

**detector 모듈은 `ParsedFrame`을 모릅니다** — `ParsedFrame` → `DeauthEvent` 변환은 호출 측(main.cpp)의 `make_deauth_event()` 헬퍼가 담당. parser와 detector의 결합을 끊어서 detector를 다른 패킷 소스(테스트 mock, 다른 파서)에 재사용 가능하게 함.

---

## 2. 전체 구조 한눈에

```
┌────────────────────────────────────────────────────────┐
│              parse_mgmt_frame()                        │
│              ↓                                         │
│              ParsedFrame (frameType=DEAUTH)            │
│              ↓                                         │
│              DeauthEvent{ts, src, ...}                 │
└────────────────────────────────────────────────────────┘
                       │
                       ▼
┌────────────────────────────────────────────────────────┐
│         DeauthFloodDetector::observe(event)            │
│                                                        │
│  ┌─────────────────────┐  ┌──────────────────────┐    │
│  │ Global window       │  │ Per-source window    │    │
│  │ deque<TimePoint>    │  │ map<Mac, Stats>      │    │
│  │ 모든 deauth 이벤트  │  │ src별 분리 추적      │    │
│  └─────────────────────┘  └──────────────────────┘    │
│                                                        │
│  각각 임계치 체크 → severity 결정 → Alert 생성        │
└────────────────────────────────────────────────────────┘
                       │
                       ▼
                  vector<Alert>
                       │
                       ▼
                  main.cpp가 출력
```

---

## 3. 핵심 알고리즘: Sliding Window via Timestamp Queue

가장 중요한 컨셉입니다. 천천히 봅시다.

### 문제
"최근 10초 동안 deauth가 몇 번 발생했나?"

### 단순한 방법 (안 좋음)
타이머로 10초마다 카운터 reset → **경계 문제**: 만약 9.9초에 9개, 10.1초에 10개가 들어오면 reset 직후라 0개로 보임.

### 우리가 쓰는 방법: timestamp queue

매 deauth마다 **그 시각**을 deque에 push:
```
deque: [t1, t2, t3, t4, ...]
```

새 이벤트가 들어올 때마다:
1. 새 timestamp를 push_back
2. **윈도우(예: 10초) 밖의 오래된 timestamp는 모두 pop_front**
3. deque의 현재 길이 = "최근 10초 안에 발생한 이벤트 수"

```cpp
void trimWindow(Window& q, TimePoint cutoff) {
    while (!q.empty() && q.front() < cutoff) q.pop_front();
}
```

### 시각화

```
시각: ─────────────────────────────────────────────►
이벤트:       *   *   *  *   *   * *  *  *
                                            │
                                            │ now
                                  └──────────┤
                                  cutoff (= now - 10s)
                                  
trimWindow 이후 deque에 남은 것: [● ● ● ● ●] (5개)
                            ↑
                            cutoff 이후의 것만
```

### 장점
- 정확함 — 어떤 시점에 봐도 정확히 "지난 10초"
- 메모리 효율적 — 윈도우 밖은 자동 정리
- O(1) 평균 amortized (각 timestamp는 한 번 push, 한 번 pop)

이 패턴을 **전역**(모든 deauth 합계)과 **per-source**(공격자 MAC별)로 각각 운용합니다.

---

## 4. `DeauthEvent` — 입력 구조

```cpp
// TimePoint는 alert.h에서 정의 (alert/detector 공유). Window는 detector 전용 (sliding window).
// using TimePoint = std::chrono::steady_clock::time_point;  // ← alert.h
using Window    = std::deque<TimePoint>;

struct DeauthEvent {
    TimePoint                ts;                  // ✅ 사용
    Mac                      src;                 // ✅ 사용
    Mac                      dst;                 // 🔵 reserved
    Mac                      bssid;               // 🔵 reserved
    std::optional<int8_t>    rssi;                // 🔵 reserved
    std::optional<uint16_t>  reasonCode;          // ✅ alert 메시지에 표시
    std::optional<int>       channel;             // ✅ per-channel cooldown 키 + alert 표시
};
// ParsedFrame → DeauthEvent 변환은 main.cpp의 make_deauth_event()가 담당 (detector 모듈은 parser 무관).
```

### 사용되는 필드 4개
- `ts`: timestamp queue에 넣을 시간
- `src`: per-source 통계의 key
- `reasonCode`: alert 메시지에 표시 (운영자가 공격 툴 추정 — reason=7 → aireplay-ng)
- `channel`: per-channel cooldown 분리 + alert에 채널 표시

### Reserved 필드 3개
현재 알고리즘은 rate-counting 위주라 안 쓰지만, `CLAUDE.md`의 Integration Requirements에 따라 **모든 정보를 detector로 전달**합니다. 미래의 enrichment 용도:

| 필드 | 활용 가능성 |
|---|---|
| `bssid` | source MAC spoofing 공격 시 BSSID별 카운터로 보완 |
| `rssi` | -30dBm이면 가까운 공격자, -70dBm이면 멀리 → 위치 추정 |
| `dst` | `FF:FF:FF:FF:FF:FF`이면 broadcast 공격, 특정 MAC이면 targeted |

지금은 안 쓰지만 데이터는 흘러오고 있으니, 알고리즘만 확장하면 즉시 활용 가능.

### 왜 steady_clock?
- system_clock은 NTP 동기화로 시간이 **점프**할 수 있음 (앞/뒤로)
- steady_clock은 **단조 증가 보장** — 윈도우 카운팅에 필수

---

## 5. `DeauthSourceStats` + `CooldownState` — per-source 상태

각 공격자 MAC마다 별도 인스턴스가 `std::map<Mac, DeauthSourceStats>`에 저장됩니다.

### `CooldownState` (전역/per-source 공통)
```cpp
// invariant: lastAlert와 lastAlertSeverity는 항상 동시 갱신
struct CooldownState {
    std::optional<TimePoint>     lastAlert;
    std::optional<AlertSeverity> lastAlertSeverity;
};
```

전역(채널별)/per-source 양쪽에서 동일한 형태로 재사용 → 코드 대칭성 확보.

### `DeauthSourceStats`
```cpp
struct DeauthSourceStats {
    Window         recent;        // 최근 윈도우 내 timestamp들
    uint64_t       total = 0;     // 누적 카운트 (모든 시간)
    TimePoint      lastSeen;      // 마지막 발생 시각
    CooldownState  cd;            // cooldown + escalation 판단용 (자세한 건 §8)
};
```

- `recent`: 그 MAC의 sliding window. 윈도우 밖 timestamp는 `trimWindow()`로 제거됨
- `total`: 누적 — alert 메시지에 표시 ("이 공격자는 평생 1500번 deauth 보냄" 같은 forensic 정보)
- `lastSeen`: idle 판단용 (오래 안 보이면 메모리에서 제거)
- `cd`: `CooldownState` 임베드 — 접근은 `stats.cd.lastAlert`, `stats.cd.lastAlertSeverity`

---

## 6. `DeauthThresholds` + `SeverityTier` — 임계치

```cpp
// info < warn < critical 단조 증가 가정.
struct SeverityTier {
    size_t info;
    size_t warn;
    size_t critical;
};

struct DeauthThresholds {
    SeverityTier global    = {10, 20, 40};   // 전체 deauth flood
    SeverityTier perSource = {5, 10, 20};    // 같은 공격자 MAC에서 오는 flood
};
```

`SeverityTier`로 묶어 두면 `severityFor(count, thresh_.global)` 처럼 호출 시 인자 1개로 압축 가능 — 6개 평면 필드보다 명시적.

CLAUDE.md 스펙 기본값. 단위는 "윈도우(=10초) 안에 발생한 횟수".

### 왜 전역 + per-source 둘 다?
- **전역만**: 여러 공격자가 동시에 쏘면 합산되어 잘 잡힘. 하지만 한 명이 천천히 쏘면 못 잡음
- **per-source만**: 공격자가 매번 src MAC을 바꾸면 못 잡음
- **둘 다 운용**: 서로 보완. 어느 한 패턴이라도 걸리면 알람

### 왜 3단계인가
공격 강도에 따른 대응 차별화:
- `info`: "뭔가 의심스러움" — 로그만
- `warn`: "공격 가능성 높음" — 운영자에게 notify
- `critical`: "확실한 공격" — 자동 대응 트리거

---

## 7. `DeauthFloodDetector` 클래스 — 본체

### 생성자
```cpp
DeauthFloodDetector(
    std::chrono::milliseconds window         = std::chrono::seconds(10),
    DeauthThresholds          thresh         = {},
    std::chrono::milliseconds cooldown       = std::chrono::seconds(3),
    std::chrono::milliseconds sourceIdleTimeout = std::chrono::minutes(5));
```

| 파라미터 | 의미 | 기본값 |
|---|---|---|
| `window` | sliding window 크기 — 몇 초 안의 이벤트를 셀지 | 10초 |
| `thresh` | info/warn/critical 임계치 | 10/20/40 (global) |
| `cooldown` | 같은 severity 알람의 최소 간격 (스팸 방지) | 3초 |
| `sourceIdleTimeout` | source가 이만큼 안 보이면 메모리에서 제거 | 5분 |

### Public API
```cpp
std::vector<Alert> observe(const DeauthEvent& event);  // 핵심. Thread-safe.
size_t globalCount() const;                          // 전역 윈도우 카운트 (lock 후 스냅샷)
size_t trackedSources() const;                       // 추적 중인 source 수 (lock 후 스냅샷)
std::optional<DeauthSourceStats> statsFor(const Mac& src) const;  // 특정 src 통계 스냅샷
```

모든 메서드 **thread-safe** — 듀얼 어댑터 운용 시 여러 capture thread가 동시 호출해도 안전 (내부 `std::mutex`로 직렬화).

---

## 8. `observe()` 흐름 — 핵심 메서드

`observe()` 자체는 **orchestration 레이어**입니다. 세부 처리는 `processGlobalEvent()` / `processPerSourceEvent()` 두 private helper에 위임:

```cpp
std::vector<Alert> DeauthFloodDetector::observe(const DeauthEvent& event) {
    std::lock_guard<std::mutex> lock(mtx_);     // ⓪ thread-safe 진입
    std::vector<Alert> alerts;

    // ① timestamp 클램핑 (단조성 보장)
    const TimePoint now = globalEvents_.empty()
        ? event.ts
        : std::max(event.ts, globalEvents_.back());
    const TimePoint cutoff = now - window_;

    // ②③ 전역 차원: 윈도우 갱신 + alert 평가/발사
    processGlobalEvent(event, now, cutoff, alerts);

    // ④⑤ per-source 차원: 윈도우/통계 갱신 + alert 평가/발사
    processPerSourceEvent(event, now, cutoff, alerts);

    // ⑥ idle source 정리
    forgetIdleSources(now);
    return alerts;
}
```

`observe()`는 위에서 아래로 읽으면 흐름이 한눈에 보임. **각 차원(global / per-source)의 세부 로직은 self-contained helper로 분리** — 같은 시그니처 `(event, now, cutoff, alerts)`로 대칭 호출.

### `processGlobalEvent()` 본문
```cpp
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

    /* Alert 데이터 (count, window, channel, ...) push + gcd 갱신 */
}
```

### `processPerSourceEvent()` 본문
```cpp
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

    /* Alert 데이터 (count, window, channel, reasonCode, total) push + stats.cd 갱신 */
}
```

두 helper는 거의 평행 구조 — `globalEvents_` ↔ `stats.recent`, `gcd` ↔ `stats.cd`, `thresh_.global` ↔ `thresh_.perSource`.

### Alert는 **데이터 전용** — 메시지 빌드는 consumer 책임

`Alert` 구조체에 미리 포맷된 string을 박아두지 않습니다. detector는 *"어떤 일이 일어났는지"* 정보만 채우고, 표현(plaintext/JSON/webhook)은 외부 consumer가 결정:

```cpp
// alert.h — TimePoint alias도 여기 정의 (alert/detector가 공유)
using TimePoint = std::chrono::steady_clock::time_point;

enum class AlertScope { global, perSource };   // 의도 명시 — source 유무 추론 안 함

struct Alert {
    AlertSeverity             severity;
    AlertScope                scope;        // global vs perSource
    TimePoint                 ts;
    std::optional<Mac>        source;       // perSource인 경우만 set
    size_t                    count;
    std::chrono::milliseconds window;
    std::optional<int>        channel;
    std::optional<uint16_t>   reasonCode;   // perSource만 의미
    uint64_t                  total = 0;    // perSource 누적 (global은 0)
};
```

`scope` 필드는 `source.has_value()`로도 알 수 있지만 **의도 명시용 redundancy**. `format_alert(a)`가 `a.scope == AlertScope::global` 같이 자명한 분기를 사용 가능.

`main.cpp`의 `format_alert()`가 이 데이터를 plaintext 한 줄로 포맷합니다 (예: `"global deauth flood: 50 events in last 10000ms (latest: ch=11)"`). 미래에 JSON output, Slack webhook 등 추가하려면 새 formatter만 작성하면 됨 — **detector는 손 안 댐**. 탐지(`DeauthFloodDetector`)와 전달(formatter)의 책임이 분리됨.

`mtx_`는 `mutable` 멤버 — `globalCount()`/`trackedSources()`/`statsFor()` 같은 const 조회 메서드에서도 락 가능. private helper (`trimWindow`/`severityFor`/`shouldAlert`/`processGlobalEvent`/`processPerSourceEvent`/`forgetIdleSources`)는 caller가 락 잡은 상태에서만 호출되는 invariant.

### ① Timestamp 클램핑 — 왜?
```cpp
const TimePoint now = globalEvents_.empty()
    ? event.ts
    : std::max(event.ts, globalEvents_.back());
```

`steady_clock`은 단조이지만, 만약 외부에서 ts를 주입(테스트나 미래의 확장)할 때 **역전된 timestamp**가 들어올 수 있습니다. 만약 그렇게 되면:
- deque는 정렬된 상태가 깨짐
- `trimWindow()`가 잘못 동작 (front()보다 작은 게 뒤에 있을 수 있음)

방어책: 들어온 ts가 직전 최대값보다 작으면 **직전 최대값을 사용**. deque 정렬성 보장.

### ② / ④ 윈도우 갱신
이미 §3에서 본 push + trimWindow 패턴.

### ③ / ⑤ Severity 평가
```cpp
static std::optional<AlertSeverity> severityFor(size_t count,
                                                const SeverityTier& tier) {
    if (count >= tier.critical) return AlertSeverity::critical;
    if (count >= tier.warn)     return AlertSeverity::warn;
    if (count >= tier.info)     return AlertSeverity::info;
    return std::nullopt;
}
```

높은 임계치부터 검사 — count=50이면 critical 반환 (warn/info도 만족하지만 가장 강한 게 우선).

### ⑥ Idle source 정리 (§10에서 자세히)

---

## 9. Cooldown + Escalation 로직 — `shouldAlert()`

가장 미묘한 부분. 두 가지 상충하는 요구사항:

1. **알람 스팸 방지**: 같은 상황 반복 알람 안 됨 → 최소 3초 간격
2. **escalation 즉시 알림**: 상황이 악화되면 (INFO → WARN → CRITICAL) **cooldown 무시하고** 즉시 알림

```cpp
bool DeauthFloodDetector::shouldAlert(const CooldownState& cd,
                                      AlertSeverity        currentSev,
                                      TimePoint            now) const
{
    if (!cd.lastAlert.has_value()) return true;                 // 첫 알람은 무조건
    if (currentSev > cd.lastAlertSeverity.value()) return true; // escalation은 즉시
    return (now - cd.lastAlert.value()) >= cooldown_;           // 같거나 낮은 severity는 cooldown 적용
}
```

`CooldownState`를 통째로 받음으로써 인자 4개 → 3개로 감소. 전역/per-source 둘 다 `CooldownState&` 한 형태로 호출 가능 — 호출 측 평행성 확보.

### 시나리오 예시
window=10s, cooldown=3s 가정. count의 시간별 추이:

```
t=0  : count=10 (INFO 임계치) → INFO 발사, lastAlert=0, lastSev=INFO
t=1  : count=15 → severity=INFO, currentSev == lastSev → cooldown 안 풀림 → skip
t=2  : count=20 (WARN 임계치) → severity=WARN > INFO → escalation, 즉시 발사 !
                                  lastAlert=2, lastSev=WARN
t=3  : count=22 → severity=WARN, 같음, cooldown 안 풀림 → skip
t=5  : count=22 → severity=WARN, cooldown 풀림(>= 3s) → 발사 (반복 알림)
t=6  : count=40 (CRITICAL 임계치) → escalation, 즉시 발사 !
```

만약 escalation 룰이 없었다면, t=2의 CRITICAL을 t=3에야 받게 됨 — 보안 사고에서 3초는 큼.

### 왜 `cd.lastAlertSeverity.value()`를 그냥 부르나? (예외 위험)
`cd.lastAlert`가 set이면 `cd.lastAlertSeverity`도 같이 set됨 — 호출 측에서 둘을 동시에 갱신:
```cpp
gcd.lastAlert         = now;   // gcd = globalCooldowns_[channelKey]
gcd.lastAlertSeverity = sev.value();
```

이 invariant가 깨지면 `bad_optional_access` 예외 발생 → 프로세스 즉시 죽음. **silent corruption보다 fast-fail이 안전**하다는 결정.

### 전역 cooldown은 **채널별로 분리**
ChannelHopper가 채널을 바꾸면 사실상 다른 RF 환경에서 sniff하는 셈입니다. 채널 1에서 INFO alert 후 cooldown 3초가 적용되는데, 그 사이 채널 11로 hop해서 별도 공격을 발견했다면 — 이 새 공격을 cooldown으로 막으면 안 됩니다.

해결: 전역 cooldown을 `std::map<int, CooldownState>` 로 채널별 분리.

```cpp
const int channelKey = event.channel.value_or(-1);  // 채널 정보 없으면 -1 키
CooldownState& gcd = globalCooldowns_[channelKey];
if (shouldAlert(gcd, sev, now)) {
    // 이 채널의 cooldown만 확인. 다른 채널의 alert는 영향 없음.
}
```

per-source cooldown은 그대로 단일 trackr (source MAC은 채널과 독립적인 신원).

---

## 10. 메모리 관리 — `forgetIdleSources()`

### 문제
공격자가 매번 random source MAC을 spoofing하면 `sources_` 맵이 무한히 커집니다. 장기 실행 daemon이면 메모리 누수.

### 해결
주기적으로 "오래 안 보인 source"는 제거.

```cpp
void DeauthFloodDetector::forgetIdleSources(TimePoint now) {
    // throttle: 너무 자주 스캔하지 않음
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
```

### 정책
- **30초마다** 한 번 스캔 (`removalInterval_=30s` 하드코딩, 매 observe()마다 스캔하면 비효율적)
- `recent`가 비어있고 (윈도우 내 활동 없음) + `lastSeen`이 `sourceIdleTimeout_`(=5분)보다 오래된 source 제거

### 활성 source는 절대 안 지움
`recent`가 비어있다는 건 윈도우 내 활동 0건 = 사실상 inactive. 활성 공격자는 `recent.size() > 0`이라 안전.

### 누적 통계 손실
제거된 source의 `total` 카운트는 사라집니다. 5분간 활동 없는 source의 누적은 잊어도 무방하다는 trade-off. 만약 영구 기록이 필요하면 별도 persistent store가 필요 (현재 범위 밖).

---

## 11. 왜 `std::map`인가? (not `unordered_map`)

`sources_`는 `std::map<Mac, DeauthSourceStats>`.

### 처음엔 `unordered_map`이었음
빠른 lookup(O(1))을 위해 hash table 선택 → 하지만 `std::hash<Mac>` specialization을 직접 만들어야 했고, `std` namespace에 사용자 코드 추가하는 부담.

### 왜 `std::map`으로 바꿨나
- N(추적 중인 source 수)이 보통 수십 ~ 수백 정도 — 실측 시 무시 가능한 차이
- `std::map`은 `operator<`만 있으면 OK (Mac에 이미 있음)
- hash 코드 surface 없어짐 → mac.h 12줄 감소

**결론: 작은 N에선 hash table이 over-engineering**. 큰 N이 진짜 측정되면 그때 다시 hash로.

---

## 12. 전체 lifecycle 시나리오

### 시나리오 A: 평화로운 시간
```
detector 생성 — globalEvents_=[], sources_={}
정상 deauth (가끔 1-2개) 들어옴
  → globalEvents_=[t1], sources_={MacA: {[t1], total=1}}
  → count=1 < info(10), severity=nullopt
  → alerts.push 안 함, observe() 반환 vector 비어있음
main.cpp: alerts 출력 안 함
```

### 시나리오 B: 단일 공격자 deauth flood (ch=11에서 aireplay-ng)
```
공격자 MAC AA:BB:CC가 ch 11에서 1초에 10번 deauth 송신 (reason=7)
t=0~1초: 10개 들어옴 (모두 ch=11, reason=7)
  per-source MacAA의 recent=[t1..t10], count=10 >= perSource.info(5)
  → severity=info, 첫 alert이라 즉시 발사
  → "deauth from AA:BB:CC: 10 events in last 10000ms (total=10, latest: ch=11, reason=7)"
t=1~2초: 또 10개
  count=20 >= perSource.warn(10) → severity=warn
  escalation (info → warn), cooldown 무시 → 즉시 발사
t=2~3초: 또 10개
  count=30 > perSource.critical(20) → severity=critical
  escalation (warn → critical), 즉시 발사
```

운영자는 `reason=7` 보고 즉시 "aireplay-ng 시그니처" 파악 가능.

### 시나리오 C: 분산 공격 (여러 MAC)
```
공격자가 5개 MAC을 번갈아 spoofing, 초당 20번, 모두 ch=6
per-source 카운터: 각 MAC은 분당 4번 → 임계치 미달
전역 카운터 (ch=6): 초당 20번, 10초면 200번 → global.critical(40) 훌쩍 넘김
  → ch=6 전역 critical alert 발사
  → "global deauth flood: 200 events in last 10000ms (latest: ch=6)"
```

### 시나리오 E: 채널 hopping 중 다른 채널 발견 (per-channel cooldown 효과)
```
듀얼 어댑터: fast-iface가 1, 6, 11 순환 중
t=0   : ch=1 에서 12개 deauth → INFO alert 발사
        globalCooldowns_[1] = {lastAlert=0, severity=INFO}
t=0.5 : hopper가 ch=6으로 이동
t=1   : ch=6 에서 별도 attacker가 15개 deauth
        globalCooldowns_[6] 은 fresh → 즉시 INFO alert
        "global deauth flood: ... (latest: ch=6)"
        (이전엔 ch=1의 cooldown이 ch=6 alert을 막았을 것)
```

### 시나리오 D: idle 정리
```
공격자 MacZ가 t=0에 100개 보냄
  → sources_[MacZ]에 entry 생성, total=100, lastSeen=0
공격자 사라짐, 평화로움
t=300초 (5분 후), 다른 누군가 deauth 보냄 → observe() 호출
  → forgetIdleSources(now=300) 실행
  → MacZ의 recent.empty() && (300 - 0) > 300 (5min) → erase
  → sources_ 맵에서 MacZ 사라짐
```

---

## 13. 주의사항 / 한계

### 정상 deauth와 공격 구분의 한계
임계치 기반이라 "정상이지만 deauth 많이 보내는 AP"가 false positive 될 수 있음 (예: AP 재부팅 시 모든 client 동시 disconnect). reasonCode를 alert에 표시하긴 하지만 알고리즘 자체에는 반영 안 됨 — 운영자가 메시지의 `reason=X`를 보고 판단해야 함.

향후 확장 여지: reason code의 분포(같은 reason 반복 = 공격 시그니처)를 weighting에 반영.

### Spoofing에 부분 취약
src MAC을 매번 바꾸는 공격은 per-source 카운터로 못 잡음 — 전역 카운터가 backstop. 전역 카운터는 채널별로 cooldown만 분리되고 카운팅은 통합이므로, 한 채널에서 분산 공격이면 잘 잡힘. 다만 spoofing 패턴이 전역 임계치(40/10s) 아래로 들어오면 놓침.

향후: bssid 필드를 활용해 BSSID별 카운터 추가하면 spoofing 더 강건해짐.

### Channel hopping과 부분 커버리지
ChannelHopper 사용 시 detector는 어댑터가 sniff하는 채널의 이벤트만 받음. 단일 어댑터로 11개 채널을 5.5초 cycle로 돌면 각 채널은 ~9% 시간만 감시됨.

**해결책 (이미 적용)**: 듀얼 어댑터 모드 (`wips-parser mon0 mon1`)에서 한 어댑터는 빠르게 sweep, 다른 어댑터는 DFS 전담. 두 어댑터가 같은 detector를 공유하므로 커버리지↑.

### per-channel 통계 미세부족
현재 전역 cooldown은 채널별로 분리됐지만, **윈도우 카운트 자체는 채널 합산** (`globalEvents_`는 모든 채널 통합 deque). 즉 ch 1에서 5개 + ch 11에서 7개면 globalCount=12. 이는 두 채널 관점에서 각각 "global=12" alert 발사 가능 (cooldown만 분리).

이게 의도된 동작: "전체 deauth 부하"를 측정한다는 의미. 채널별 독립 카운팅이 필요하면 향후 `std::map<int, ChannelStats>` 추가.

---

## 14. 디버깅 체크리스트

| 증상 | 가능한 원인 | 확인 방법 |
|---|---|---|
| Deauth 많이 보는데 alert 없음 | window/threshold 매칭 실패 | `globalCount()` 호출해서 현재 윈도우 카운트 확인 |
| 한 번만 alert 뜨고 끝 | cooldown 작동 중 | 3초 이상 기다려서 다시 발사되는지 확인 |
| 메모리 사용량 계속 증가 | 제거 안 됨 | `trackedSources()`로 사이즈 확인. 5분 이상 활성 source가 누적되면 정상 |
| Same source인데 매번 새 entry | Mac::operator== 오동작 | `statsFor(MacXX)`로 같은 source의 entry가 있는지 확인 |
| escalation 안 됨 | shouldAlert 로직 버그 | severity 전이 시 즉시 alert인지 확인 |

---

## 15. 향후 확장 아이디어

### Reserved 필드 활용
- **bssid 카운터 추가**: source 외에 BSSID별 추적 → spoofing 공격에 더 강건
- **reasonCode 분포 분석**: 공격 툴 fingerprint
- **rssi 분포**: 단일 위치 vs 분산 공격 구분

### 알고리즘 개선
- **adaptive threshold**: 시간대별 기준 자동 조정 (낮은 트래픽 시간엔 낮은 threshold)
- **per-channel cooldown**: 채널별 독립 cooldown
- **persistent stats**: 제거된 source도 SQLite 등에 저장해 누적 기록 유지

### 운영
- **alert webhook**: Slack/Discord 등으로 알림 전송
- **rate limiting**: alert 자체에 rate limit (예: 분당 최대 10개)
- **silent mode**: 특정 BSSID/MAC 화이트리스트

### 통합
- **Channel Hopper coordination**: alert 발사 시 hopper에게 "이 채널 더 오래 머물러"
- **Auto-defense**: critical alert 시 자동으로 wireless IDS 차단 룰 추가
