# 학습 노트 — 코드의 헷갈리는 부분 답변 모음

코드 곳곳에 *"이거 다시 봐야 함"*, *"왜 이렇게 했지?"* 같은 학습용 주석을 달아두셨는데, 각 부분에 대한 설명을 한 곳에 모았습니다.

코드의 해당 주석은 정리(제거)하셔도 되고, 이 문서를 옆에 두고 참고하면서 두셔도 됩니다.

---

## 📁 `include/detector/deauth_detector.h`

### L35 — `/*애는 더 공부하기*/` (`struct DeauthSourceStats`)

```cpp
struct DeauthSourceStats {
    Window         recent;
    uint64_t       total = 0;
    TimePoint      lastDeauthSeen;
    CooldownState  cd;     // per-source cooldown
};
```

**무엇인가**: 한 명의 공격자(source MAC)에 대해 누적되는 통계 모음.

| 필드 | 역할 | 언제 갱신? |
|---|---|---|
| `recent` | 그 source의 sliding window timestamp들 | 매 deauth마다 push, 오래된 것 trim |
| `total` | 누적 카운트 (영구) | 매 deauth마다 +1 — *"평생 몇 번 deauth 보냈는지"* |
| `lastDeauthSeen` | 마지막 deauth 시각 | 매 deauth마다 갱신 — `forgetIdleSources`가 idle 판정에 사용 |
| `cd` | 이 source 전용 cooldown 상태 | alert 발사 시 갱신 — 같은 source에 대해 스팸 방지 |

**왜 이 필드들?**
- `recent`: *"최근 10초 동안 몇 번?"* 답하려고 → sliding window 자료구조
- `total`: alert 메시지에 *"이 공격자가 평생 1500번 deauth 보냈음"* 같은 forensic 정보 표시
- `lastDeauthSeen`: 메모리 관리용 — 5분 안 보이면 잊기 위해 마지막 본 시각 기록
- `cd`: cooldown은 source별로 독립 (한 source의 cooldown이 다른 source 알람 막으면 안 됨)

**왜 전역(`globalEvents_`)에는 `lastDeauthSeen`이 없는가?**
전역은 모든 source 합산이라 "마지막 봤다" 개념이 무의미. 전역은 절대 forget되지 않음.

---

### L64 — `/*애도 공부하기*/` (`observe()` 선언)

```cpp
std::vector<Alert> observe(const DeauthEvent& event);
```

**무엇인가**: detector의 **유일한 입력 진입점**.

**시그니처 풀이**:
- 입력: `const DeauthEvent& event` — *"deauth 1건이 들어왔다"*
- 출력: `std::vector<Alert>` — *"이 이벤트로 인해 발사된 alert 0~2개"*

**왜 vector를 반환?**
한 이벤트로 alert이 **동시에 2개 발사 가능**:
- 전역 카운트가 임계치 넘으면 → global alert
- per-source 카운트도 임계치 넘으면 → per-source alert

대부분은 0개 (임계치 미달) 또는 1개. 동시에 둘 다 트리거되는 케이스도 있어서 vector.

**Thread-safe인 이유**: 내부에서 `mtx_` 락 잡음. 듀얼 어댑터의 두 capture thread가 동시 호출해도 안전.

---

## 📁 `src/detector/deauth_detector.cpp`

### L16 — `/*애는 다시 볼것*/` (`trimWindow`)

```cpp
void DeauthFloodDetector::trimWindow(Window& q, TimePoint cutoff) {
    while (!q.empty() && q.front() < cutoff) q.pop_front();
}
```

**무엇 하는가**: deque의 **앞쪽**에서 cutoff보다 오래된 timestamp들을 모두 pop.

**왜 앞쪽만?**
deque의 timestamp가 **시간순으로 push**되므로, 가장 오래된 게 항상 `front`. front가 cutoff 이상이면 그 뒤는 모두 cutoff 이상 → 중단.

**왜 `static`?**
멤버 변수 안 씀 (q와 cutoff만으로 동작) → 인스턴스 종속 안 됨 → `static`으로 만들 수 있음. 컴파일러 최적화에 유리하고, 호출도 인스턴스 없이 `DeauthFloodDetector::trimWindow(...)` 가능.

**시간 복잡도**: amortized O(1) per event. 한 이벤트는 한 번 push되고 한 번 pop됨.

---

### L38 — `/*애도 공부하기*/` (`forgetIdleSources`)

```cpp
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
```

**왜 필요?**
공격자가 MAC을 매번 spoofing하면 `sources_` 맵이 무한 증가 → 메모리 누수.

**3단계 구조**:

**1) Throttle (스캔 빈도 제한)**
```cpp
if (lastRemovalRun_.has_value() &&
    (now - lastRemovalRun_.value()) < removalInterval_) return;
```
매 `observe()`마다 전체 맵 스캔하면 비효율. 30초마다 한 번만 스캔.

**2) Forget 조건**
```cpp
if (stats.recent.empty() && (now - stats.lastDeauthSeen) > sourceIdleTimeout_)
```
**두 조건 모두** 만족해야 제거:
- `recent.empty()`: 최근 윈도우(10초) 내 활동 0건
- `lastDeauthSeen`이 5분 이상 전

활성 공격자는 절대 안 지워짐 — `recent`에 timestamp가 있으니까.

**3) Iterator 패턴**
```cpp
for (auto it = sources_.begin(); it != sources_.end(); ) {
    if (조건) it = sources_.erase(it);   // erase 후 반환된 다음 iterator로
    else      ++it;                      // 그냥 다음
}
```
`erase`가 iterator를 invalidate하므로 **erase의 반환값으로 진행**. C++ 컨테이너 erase의 표준 패턴.

---

### L54 — `/*뮤텍스를 왜 걸었지*/` (조회 메서드들)

```cpp
size_t DeauthFloodDetector::globalCount() const {
    std::lock_guard<std::mutex> lock(mtx_);   // ← 이거 왜?
    return globalEvents_.size();
}
```

**한 줄 답**: `globalEvents_`는 `observe()`가 동시에 수정할 수 있는 공유 상태라, **읽기도 락 잡지 않으면 race condition**.

**시나리오**:
- Thread A: `globalCount()` 호출 — `globalEvents_.size()` 읽으려는 순간
- Thread B: 같은 시점에 `observe()` 호출 — `globalEvents_.push_back()` 또는 `pop_front()` 실행 중
- 결과: deque 내부 상태가 일관성 없는 순간에 size() 읽음 → undefined behavior, 잘못된 값, 크래시 가능

**락 안 잡고 안전한 경우는?**
- `std::atomic<size_t>` 같은 타입이면 OK
- 일반 컨테이너는 절대 NO

**`mutable std::mutex`인 이유**
`const` 메서드에서도 락 잡아야 하므로 mutex만은 mutable. C++의 *"논리적 const"* 패턴 — *"외부 관찰 상태는 안 바뀌지만 내부 동기화는 필요"*.

```cpp
mutable std::mutex mtx_;   // ← const 메서드 안에서 lock 가능
```

---

### L66 — `/*애도 어렵다*/` (`statsFor`)

```cpp
std::optional<DeauthSourceStats> DeauthFloodDetector::statsFor(const Mac& src) const {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = sources_.find(src);
    if (it == sources_.end()) return std::nullopt;
    return it->second;     // ← copy!
}
```

**무엇 하는가**: 특정 src MAC의 통계 **스냅샷**을 복사해서 반환.

**왜 reference나 pointer 안 반환?**
- 호출자가 reference 들고 있는 동안 다른 thread가 `forgetIdleSources()`로 맵에서 그 entry를 erase하면 → dangling reference → UB
- 안전하게 하려면 **복사본** 반환 (락 풀고 나서도 살아있는 데이터)

**왜 `std::optional`?**
*"존재 안 함"* 을 표현. `Mac`이 맵에 없으면 빈 stats 반환 대신 `nullopt`로 *"이 source는 추적 안 함"* 명시.

**복사 비용?**
`DeauthSourceStats`는 `Window`(deque) 멤버를 가짐 → 깊은 복사. 비싸다면 비쌈. 다만 호출 빈도가 낮은 디버그용 API라 OK.

---

### L74 — `/*어려웡 ㅎ*/` (`observe()` 본체)

```cpp
std::vector<Alert> DeauthFloodDetector::observe(const DeauthEvent& event) {
    std::lock_guard<std::mutex> lock(mtx_);
    std::vector<Alert> alerts;

    // ① timestamp 클램핑
    const TimePoint now = globalEvents_.empty()
        ? event.ts
        : std::max(event.ts, globalEvents_.back());
    const TimePoint cutoff = now - window_;

    // ② 전역 차원 처리
    processGlobalEvent(event, now, cutoff, alerts);
    // ③ per-source 차원 처리
    processPerSourceEvent(event, now, cutoff, alerts);
    // ④ idle 정리
    forgetIdleSources(now);

    return alerts;
}
```

**6단계 흐름**:

1. **Lock**: thread-safe 보장
2. **alerts 빈 vector 준비**: helper들이 채울 출력 버퍼
3. **now 계산 + 클램핑**: 들어온 ts가 직전 최대보다 작으면 직전 최대를 사용 → deque 단조성 보장 (`trimWindow`의 정확성에 필수)
4. **cutoff 계산**: `now - window_` (10초 전)
5. **두 차원 처리**: 전역 + per-source 각각 윈도우 갱신 + 임계치 체크 + alert 발사
6. **idle cleanup + return**

**왜 `std::max` 클램핑?**
보통 `steady_clock`은 단조 증가지만, 만약 테스트에서 가짜 시간 주입하거나 미래 확장에서 역전된 ts가 들어오면 deque 정렬성이 깨짐 → trimWindow 잘못 동작. 방어책으로 *"직전 최대값을 사용"*.

**왜 alerts를 reference로 helper에 넘김?**
helper가 alert을 *"push할 수도 있고 안 할 수도 있음"* — 반환값으로 받기보다 `vector&`에 직접 push가 깔끔.

**왜 `processGlobal` 다음 `processPerSource`?**
순서가 의미적으론 무관 (각자 자기 상태만 건드림). 다만 alert 발사 순서가 일관되도록 정해놓은 것 — 전역이 먼저, per-source가 나중.

---

## 📁 `src/hopper/channel_hopper.cpp`

### L6 — `/*애도 좀 걸림*/` (생성자)

```cpp
ChannelHopper::ChannelHopper(std::string iface, ChannelHopConfig cfg)
    : iface_(std::move(iface)), cfg_(std::move(cfg)) {}
```

**핵심**: **"sink parameter + std::move"** idiom — 복사 회피.

**파라미터를 값으로 받는 이유**:
- 호출자가 rvalue(임시값) 주면 → 이동
- lvalue 주면 → 복사 (1번)
- 어느 쪽이든 함수 내부에선 일회용 사본

**`std::move`로 멤버 초기화하는 이유**:
- `std::move`는 *"이 값 더 안 쓸 거니까 내부 데이터 가져가도 됨"* 표시
- 멤버 이동 생성자 호출 → 힙 할당된 string/vector 내용 포인터만 swap (복사 0)

**전체 비용**:
- rvalue 인자: 이동 2회, 복사 0회
- lvalue 인자: 복사 1회 + 이동 1회

상세 설명은 이전 대화 참고 (sink parameter idiom).

---

### L29 — `/*여기서 worker를 왜 깨우는 거지?*/` (`stop()`의 `notify_all`)

```cpp
void ChannelHopper::stop() {
    running_.store(false);
    stopCv_.notify_all();   // ← 이거 왜?
    if (worker_.joinable()) worker_.join();
}
```

**한 줄 답**: 깨우지 않으면 worker가 **dwell time(최대 2초)을 다 기다린 후에야** 종료 신호를 인식.

**시나리오** (notify_all 없을 때):
1. main thread: `running_.store(false)` 호출
2. worker thread: `sleepOrUntilStop(2000ms)` 안에서 자고 있음 — `running_` 변화 모름
3. worker: 2초 다 자고 일어나서 `running_.load()` 확인 → false → 종료
4. main: `worker_.join()` 에서 2초 대기

→ **Ctrl+C 누르고 종료까지 최대 2초 hang**.

**`notify_all` 있을 때**:
1. main: `running_.store(false)` 호출
2. main: `stopCv_.notify_all()` 호출 → worker 즉시 깨어남
3. worker: predicate (`!running_.load()`) 평가 → true → 자고 있던 `wait_for` 즉시 반환
4. worker: while 루프 빠져나옴 → 종료
5. main: `worker_.join()` 즉시 성공

→ **shutdown latency < 1ms**.

**condition variable의 본질**: *"내가 자고 있을 때 누가 깨워줄 수 있어야 즉시 반응 가능"*. atomic 변수 변화는 자고 있는 thread를 못 깨움 — cv가 그 역할.

---

### 🔍 깊게 보기 — `stopMtx_` mutex와 worker thread의 상호작용

`stop()`과 `sleepOrUntilStop()`을 같이 봐야 전체 그림이 보입니다. **두 thread**가 어떻게 mutex와 cv로 협력하는지 자세히 풀어볼게요.

#### 코드 한눈에

```cpp
// main thread가 호출
void ChannelHopper::stop() {
    running_.store(false);
    stopCv_.notify_all();
    if (worker_.joinable()) worker_.join();
}

// worker thread가 호출 (run() 안에서)
void ChannelHopper::sleepOrUntilStop(std::chrono::milliseconds dur) {
    std::unique_lock<std::mutex> lock(stopMtx_);
    stopCv_.wait_for(lock, dur, [this] { return !running_.load(); });
}
```

#### 등장 인물 3명

| 멤버 | 역할 |
|---|---|
| `running_` (atomic bool) | 실행 중인지 표시. atomic이라 자체적으로 thread-safe. |
| `stopMtx_` (mutex) | cv가 요구하는 lock. **공유 데이터 보호용 아님** |
| `stopCv_` (condition_variable) | "잠든 thread를 깨우는" 메커니즘 |

#### 첫 의문 — "왜 mutex가 필요한가? `running_`는 이미 atomic인데?"

이게 가장 헷갈리는 부분. 답: **mutex는 `running_`을 보호하는 게 아니라, cv의 동작에 필요한 도구.**

`cv.wait_for(lock, ...)` 호출은 C++ 표준이 **반드시 `unique_lock` 인자를 요구**합니다. 왜? cv 내부 동작 때문:

```
wait_for(lock, dur, pred) 의 내부 동작:
  1. lock이 이미 잡혀있다고 가정
  2. while (!pred()):
       a. lock 풀기 (unlock)
       b. dur만큼 잠들기 또는 notify 받으면 깨기
       c. lock 다시 잡기 (lock)
       d. pred 다시 평가
  3. 반환
```

**핵심**: 잠들기(b) 직전에 lock을 푸는 동작이 **atomic** 해야 함. *"pred 확인했는데 false → 막 자려는 순간 다른 thread가 notify → 자고 있지 않아서 못 깨어남"* 같은 lost-wakeup 방지.

mutex가 없으면 cv 자체가 이 보장을 못 함. 그래서 **명목상의 mutex라도 반드시 필요**.

#### 두 thread의 시간 흐름

**시나리오 A: 정상 동작 (Ctrl+C로 종료)**

```
시간 ────────────────────────────────────────►

main thread:                          worker thread:
                                      ┌─ run() 안 ─┐
                                      │ sleepOrUntilStop(2000ms) 호출
                                      │   lock(stopMtx_)           ← lock 잡음
                                      │   wait_for 진입
                                      │     pred() = !running_ → false
                                      │     lock 풀고 잠듦         ← 여기서 자고 있음
                                      │
[사용자 Ctrl+C]                       │   . . . zzz . . .
stop() 호출                          │
  running_.store(false)              │
  ←─── 동시에 ───────────────────────┤   (자는 동안 running_=false 됨)
  notify_all()  ─────────────────────►│   ← 깨어남! 알람!
                                      │     lock 다시 잡음
                                      │     pred() = !running_ → true!
                                      │     wait_for 반환
                                      │   lock 풀고 함수 종료
                                      └─ 다시 while 체크: running_=false → 루프 exit
  worker.join() ──────────────────────► (worker 끝나서 즉시 반환)
[프로그램 종료]
```

**시나리오 B: dwell 자연 만료 (정상 호핑)**

```
worker thread:
  sleepOrUntilStop(500ms)
    lock(stopMtx_)
    wait_for:
      pred() = !running_ → false (running 중이니까)
      lock 풀고 잠듦
      . . . 500ms 지남 . . .
      timeout 발생 (notify는 없었음)
      lock 다시 잡음
      pred() = false (여전히)
      wait_for가 false 반환 (timeout)
  lock 풀고 함수 종료
다음 채널로 이동
```

**시나리오 C: 만약 mutex 없다면 (가상)**

```
worker:                              main:
  pred() = running_ true              
  ← 여기서 OS가 worker를 잠시 중단    
                                     running_.store(false)
                                     notify_all()  ← 아무도 안 자고 있음!
                                                      notification 사라짐
  worker 재개
  실제로 자기 시작
  → 영원히 깨어나지 않음 (notify는 이미 사라짐)
  → deadlock 또는 timeout까지 hang
```

mutex가 있으면:
- worker가 pred 평가하는 동안 lock 잡고 있음
- main이 notify_all 호출 시점에 worker는 이미 wait_for 안에서 *"잠들었거나, 잠들기 직전이지만 lock을 잡고 있음"*
- cv 구현이 이 상태를 올바르게 처리 (notify를 *"대기 중 또는 곧 대기할"* thread로 전달)

#### `unique_lock` vs `lock_guard` — 왜 `unique_lock`?

`sleepOrUntilStop`에서 `unique_lock`을 씁니다:
```cpp
std::unique_lock<std::mutex> lock(stopMtx_);
stopCv_.wait_for(lock, dur, [this] { return !running_.load(); });
```

이유: `wait_for`가 **lock을 풀었다 다시 잡는 동작**을 해야 함. `lock_guard`는 RAII 단방향(잠금만 + 소멸 시 풀기)이라 *"잠시 풀었다 다시"* 가 불가능. `unique_lock`은 그게 가능한 더 유연한 lock.

| | `lock_guard` | `unique_lock` |
|---|---|---|
| 잠금 시점 | 생성 시 1번 | 생성 시 + 수동 lock/unlock 가능 |
| cv와 함께 사용 | ❌ 불가 | ✅ 필수 |
| 오버헤드 | 더 가벼움 | 약간 더 무거움 |
| 용도 | 단순 critical section | cv, 조건부 잠금, ownership 이동 |

#### `stop()`이 mutex를 안 잡는 이유

```cpp
void ChannelHopper::stop() {
    running_.store(false);
    stopCv_.notify_all();   // ← lock 안 잡음!
}
```

cv `notify_*` 호출 자체는 **lock을 요구하지 않습니다.** lock은 *"기다리는 쪽"* 만 필요.

다만 strict한 C++ 표준 패턴은 *"값 변경 직전에 lock 한 번 잡았다 풀기"* (memory fence 역할)를 권장합니다. 우리 코드는 안 하지만, `running_`이 atomic이고 `wait_for`에 timeout 있어서 실용적으로 안전 — 최악의 경우 timeout만큼 (200ms-2000ms) 늦어질 뿐 deadlock 안 됨.

#### 정리 — 한 문장씩

1. **mutex의 역할**: cv의 atomic check-and-wait을 가능하게 함
2. **mutex가 보호하는 것**: cv 내부 상태 (running_ 자체가 아님)
3. **running_이 atomic인 이유**: lock 없이 store/load 가능 (memory ordering 보장)
4. **cv가 필요한 이유**: 자고 있는 worker를 즉시 깨우려고 (atomic 변경은 자는 thread를 못 깨움)
5. **notify_all의 효과**: wait_for를 즉시 반환시킴 → predicate 재평가 → running_=false 확인 → exit
6. **unique_lock 쓰는 이유**: wait_for가 lock을 풀었다 다시 잡아야 하므로

#### 비유 — 회의실 비유

- `running_`: 칠판에 적힌 *"회의 끝났음 ✓"* 표시 (누구나 보고 확인 가능)
- `stopMtx_`: 회의실 문 (한 번에 한 명만 들어옴)
- `stopCv_`: 회의실 안 알람 시계 (다른 사람이 누르면 안에서 자는 사람 깨움)
- `worker`: 회의실에서 잠시 자고 있는 사람 (dwell 동안)
- `stop()`: 회의 끝났다고 칠판에 적고 알람 시계 누름

알람 시계만 누르면 자고 있는 사람만 깨어남. 회의실 안에 사람이 없으면 알람이 울려도 의미 없음 (lost wakeup 위험). 그래서 *"자려고 들어가는 동안엔 문(mutex)을 잡고 있어야"* 알람이 정확히 전달됨.

---

### L46 — `/*다시 보기*/` (`setChannel`의 fork/exec)

```cpp
bool ChannelHopper::setChannel(int channel) {
    char chBuf[16];
    std::snprintf(chBuf, sizeof(chBuf), "%d", channel);   // ① fork 전에 변환

    pid_t pid = fork();                                    // ② 자식 프로세스 분기
    if (pid < 0) return false;

    if (pid == 0) {
        ::execlp("iw", "iw", "dev", iface_.c_str(), "set", "channel", chBuf,
                 static_cast<char*>(nullptr));             // ③ 자식: iw로 교체
        ::_exit(127);                                      // ④ exec 실패 시 즉시 종료
    }

    int status = 0;
    if (::waitpid(pid, &status, 0) < 0) return false;     // ⑤ 부모: 자식 종료 대기
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
```

**왜 `iw` 외부 명령? 라이브러리 없나?**
- Linux 표준: `iw` (사용자 공간 도구)
- 대안 (모두 단점):
  - `iwconfig`: deprecated
  - libnl로 netlink 직접 호출: 복잡 (외부 라이브러리 의존)
  - SIOCSIWFREQ ioctl: deprecated
- `iw`가 가장 portable + 간단.

**왜 `system()` 안 쓰고 `fork()+execlp()`?**
- `system("iw ...")`: shell 거침 → 인터페이스 이름에 `;` 같은 메타문자 끼면 **shell injection** 가능
- `execlp`: 인자를 그대로 전달 → 안전

**`fork()`의 분기**:
- 부모: `pid`에 자식의 pid 받음
- 자식: `pid == 0`
- 같은 코드인데 `pid` 값으로 분기

**자식이 `execlp` 호출**:
- 자식 프로세스의 메모리를 **`iw` 명령으로 통째로 교체**
- 성공하면 그 뒤 코드 (`_exit(127)`)는 실행 안 됨
- 실패하면 `_exit(127)` 호출 → 자식 즉시 종료 (127은 "command not found" 관례 코드)

**부모가 `waitpid`로 대기**:
- 자식이 끝날 때까지 block
- 종료 상태 검사: `WIFEXITED` (정상 종료?) + `WEXITSTATUS == 0` (성공?)

**왜 `snprintf`를 fork 전에?**
fork 후 자식 프로세스에선 **async-signal-safe 함수만** 호출해야 함 (POSIX 규칙). `snprintf`는 locale 참조하므로 NOT async-signal-safe. 따라서 fork 전에 미리 변환해두고 자식은 변환된 결과만 사용.

---

### L73-74 — `summary()` 관련 주석들

```cpp
/*그냥 채널목록 사람이 보기 편하게 출력해주는 부분*/
/*애도 어렵다*/
std::string ChannelHopper::summary() const { ... }
```

**무엇 하는가**: 채널 리스트를 2.4GHz / 5GHz로 분류해서 *"2.4GHz(1,6,11) + 5GHz(36,40,...) — 500ms dwell"* 형태로 출력.

**왜 어렵게 느껴지나**:
1. **두 vector 분류**: 채널 번호 ≤ 14 → 2.4GHz, 그 외 → 5GHz
   ```cpp
   (ch <= 14 ? ch24 : ch5).push_back(ch);
   ```
   삼항 연산자로 *"어느 vector에 push할지"* 선택. 익숙하지 않으면 헷갈릴 수 있음.

2. **lambda 사용**:
   ```cpp
   auto joinCsv = [](const std::vector<int>& v) {
       std::ostringstream s;
       // ...
       return s.str();
   };
   ```
   이름 없는 함수를 함수 내부에서 정의. CSV로 연결하는 작은 헬퍼를 외부로 빼지 않고 인라인으로 둠.

3. **`ostringstream` 누적**:
   ```cpp
   std::ostringstream oss;
   oss << "2.4GHz(" << joinCsv(ch24) << ")";
   ```
   `printf` 대신 `<<` 연산자로 string 만들기 — C++ idiom.

**전반적 구조**: 분류 → 각 그룹을 CSV로 → 두 그룹을 ` + `로 연결 → dwell 붙이기. **별로 안 어려운데 익숙치 않은 패턴들이 한 함수에 모여서** 어려워 보임.

---

### L139 — `/*원형순환하는 건 알겠는데 어떻게 코드에서 돌아가는지는 이해가 안되*/`

```cpp
sleepOrUntilStop(cfg_.dwell);
idx = (idx + 1) % cfg_.channels.size();
```

**3가지가 합쳐서 원형 순환 만듦**:

| 요소 | 역할 |
|---|---|
| `while (running_.load())` | 무한 반복 |
| `cfg_.channels[idx]` | idx → 채널로 변환 |
| `idx = (idx + 1) % size` | 인덱스 전진 + 끝에서 0으로 wrap |

**`% cfg_.channels.size()` 의 역할**:
- modulo (나머지) 연산자
- idx가 size에 도달하는 순간 0으로 강제 reset
- `0, 1, 2, ..., size-1, 0, 1, 2, ...` 영원히 반복

**시각화** (channels = [1, 6, 11, 36], size=4):
```
시간 →
idx:  0  1  2  3  0  1  2  3  0  1  2  3 ...
ch:   1  6 11 36  1  6 11 36  1  6 11 36 ...
                  ↑              ↑
                  wrap!          wrap!
```

**modulo 없으면?**
```cpp
idx = idx + 1;   // ❌
// iter 5에서 idx=4 → cfg_.channels[4] = out-of-bounds = UB
```

**상세 설명은 이전 대화 참고** — line-by-line trace로 한 iteration씩 따라간 적 있음.

---

