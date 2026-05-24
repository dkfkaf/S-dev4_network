# ChannelHopper 코드 설명

`include/hopper/channel_hopper.h` + `src/hopper/channel_hopper.cpp` 의 동작과 설계를 풀어 쓴 문서.

---

## 1. 이 모듈은 무엇을 하나

Wi-Fi 어댑터의 **수신 채널을 일정 주기로 자동으로 바꿔주는** 모듈.

### 왜 필요한가
Wi-Fi는 같은 시각에 **하나의 채널만** 들을 수 있습니다. 모니터 모드 어댑터를 채널 6에 고정하면 채널 1, 11, 36 등의 트래픽은 전혀 안 보입니다. 공격자가 어떤 채널을 쓸지 모르니, **여러 채널을 빠르게 돌아가며 sniff** 해서 커버리지를 확보해야 합니다.

### 사용 위치
`main.cpp`에서 pcap 캡처 시작 직전에 ChannelHopper를 띄워두면, 별도 스레드가 알아서 채널을 돌립니다. 메인 스레드는 패킷 캡처에만 집중하면 됩니다.

```cpp
ChannelHopper hopper(ifname, ChannelHopConfig{});
hopper.start();
// ... pcap 캡처 루프 ...
hopper.stop();
```

### 두 가지 운용 모드
- **Single-adapter** (`wips-parser mon0`): 한 어댑터가 default 11개 채널(2.4 + 5GHz non-DFS)을 500ms씩 순환
- **Dual-adapter** (`wips-parser mon0 mon1`): 두 어댑터가 역할 분담
  - `mon0` (fast): `fastNonDfs()` — 11채널 200ms (빠른 sweep)
  - `mon1` (dfs):  `dfsOnly()`    — 12 DFS 채널 2000ms (DFS CAC 비용 amortize)
  
dual-adapter에서 두 ChannelHopper 인스턴스가 독립적으로 동작하고, **DeauthFloodDetector는 thread-safe하게 공유**되어 통합 통계를 유지합니다. (실제 main.cpp는 non-movable한 ChannelHopper를 vector에 담기 위해 `std::vector<std::unique_ptr<ChannelHopper>>`로 관리)

---

## 2. 전체 구조 한눈에

```
┌─────────────────────────────────────────────────┐
│                Main Thread                       │
│  - pcap_next_ex() 로 패킷 캡처                  │
│  - parse_mgmt_frame()                           │
│  - print, detector.observe()                    │
└─────────────────────────────────────────────────┘
                       │
                       │ start() / stop()
                       ▼
┌─────────────────────────────────────────────────┐
│                Worker Thread                     │
│  - 채널 목록을 순환                              │
│  - 각 채널에서 dwell time 만큼 머무름            │
│  - 채널 변경: `iw dev <iface> set channel <n>`   │
│  - 실패한 채널은 skip 표시                       │
└─────────────────────────────────────────────────┘
                       │
                       │ fork() + execlp()
                       ▼
                  외부 `iw` 명령
                       │
                       ▼
                  Linux 커널 / 드라이버
                       │
                       ▼
                  Wi-Fi 어댑터 채널 변경
```

---

## 3. `ChannelHopConfig` — 설정 구조체

```cpp
struct ChannelHopConfig {
    // 채널 리스트 상수 — default + factory 공유 (DRY)
    inline static const std::vector<int> NON_DFS_CHANNELS = {
        1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161};
    inline static const std::vector<int> DFS_CHANNELS = {
        52, 56, 60, 64, 100, 104, 108, 112, 116, 132, 136, 140};

    std::vector<int>          channels = NON_DFS_CHANNELS;
    std::chrono::milliseconds dwell    = std::chrono::milliseconds(500);

    // 듀얼 어댑터 운용용 preset
    static ChannelHopConfig fastNonDfs();   // NON_DFS_CHANNELS, 200ms dwell
    static ChannelHopConfig dfsOnly();      // DFS_CHANNELS, 2000ms dwell
};
```

### `channels` — 어떤 채널들을 순환할지 (single-adapter 기본값)
기본값은 11개 채널:
- **2.4GHz** (1, 6, 11): 서로 간섭하지 않는 3개 메인 채널 (대부분의 Wi-Fi가 여기 있음)
- **5GHz UNII-1** (36, 40, 44, 48): DFS가 아닌 5GHz 저대역
- **5GHz UNII-3** (149, 153, 157, 161): DFS가 아닌 5GHz 고대역

**기본 single-adapter 구성과 `fastNonDfs()` preset에서는 DFS 채널(52~144)을 제외**합니다. DFS는 "Dynamic Frequency Selection"으로, 레이더 감지를 위해 채널 진입 직후 일정 시간 passive (송신 금지, 수신만)이 강제됩니다. monitor mode에서도 진입 후 잠시 패킷이 안 보일 수 있어 짧은 dwell로 빠르게 sweep하는 경로에는 부적합 — 그래서 빠른 경로에선 빼두고, 듀얼 어댑터 운용 시 별도 인터페이스에서 `dfsOnly()` preset (DFS 12채널, 2000ms dwell)으로 전담 sniff하여 CAC 비용을 amortize 합니다.

### `dwell` — 각 채널에서 얼마나 머물지
기본 500ms. 너무 짧으면 비콘(보통 100ms 주기) 한두 개도 못 보고 떠나고, 너무 길면 다른 채널의 공격을 놓칠 수 있습니다. 500ms면 채널당 비콘 5개 정도 보고 떠나는 수준.

전체 순환 주기 (single-adapter): 11채널 × 500ms = **5.5초/cycle**. Deauth 탐지 윈도우가 10초니까 각 채널은 윈도우의 ~45% 시간 동안 감시됩니다.

### Static factory: `fastNonDfs()`, `dfsOnly()` — 듀얼 어댑터용
듀얼 어댑터 모드에서 어댑터 역할을 분담하기 위한 preset:

```cpp
ChannelHopConfig::fastNonDfs() {
    return {NON_DFS_CHANNELS,                  // 11채널 (default와 동일 리스트)
            std::chrono::milliseconds(200)};   // 짧은 dwell
}

ChannelHopConfig::dfsOnly() {
    return {DFS_CHANNELS,                      // 12 DFS 채널
            std::chrono::milliseconds(2000)};  // 긴 dwell
}
```

채널 리스트가 **각 preset에 박혀있던 hardcoded array → `NON_DFS_CHANNELS`/`DFS_CHANNELS` 상수 참조**로 바뀌어 한 곳에서 관리됨. default(`ChannelHopConfig{}`)와 `fastNonDfs()`가 같은 NON_DFS 리스트를 공유한다는 사실이 코드에 명시.

**왜 이런 분담?**
- `fastNonDfs`: non-DFS 채널은 진입 비용이 작아 짧은 dwell로 빠른 sweep 가능. 200ms × 11 = 2.2초 cycle
- `dfsOnly`: DFS 진입에 CAC 시간이 있어 비용 큼. 한 번 진입하면 2초간 머물러 amortize. 2000ms × 12 = 24초 cycle

두 어댑터의 채널 집합이 disjoint이므로 같은 deauth 패킷이 양쪽에서 잡힐 일 없음 → 중복 카운트 0.

---

## 4. `ChannelHopper` 클래스 — 핵심

### Public 인터페이스 4개

```cpp
class ChannelHopper {
public:
    ChannelHopper(std::string iface, ChannelHopConfig cfg);  // 생성
    ~ChannelHopper();                                         // 자동 stop
    void start();                                             // 워커 시작
    void stop();                                              // 워커 정지
    std::optional<int> currentChannel() const;                // 현재 채널 조회
    std::string summary() const;                              // 사람용 요약 문자열
};
```

### Copy 금지
```cpp
ChannelHopper(const ChannelHopper&)            = delete;
ChannelHopper& operator=(const ChannelHopper&) = delete;
```
스레드와 mutex/cv를 멤버로 가지므로 복사 의미가 없음. 명시적으로 금지.

### Private 멤버들

```cpp
private:
    void run();                              // 워커 스레드 본체
    bool setChannel(int channel);            // iw 호출 1회

    std::string               iface_;        // 인터페이스 이름 (예: "mon0")
    ChannelHopConfig          cfg_;          // 설정 사본
    std::thread               worker_;       // 워커 스레드
    std::atomic<bool>         running_{false};      // 실행 중 플래그
    std::atomic<int>          currentChannel_{-1};  // 마지막으로 설정된 채널

    std::mutex                stopMtx_;      // cv 코디네이션용
    std::condition_variable   stopCv_;       // dwell 대기 중단용
```

핵심은 `running_`과 `stopCv_`입니다 — main 스레드와 worker 스레드 사이의 신호 메커니즘.

---

## 5. `start()` 동작 — 워커 시작

```cpp
void ChannelHopper::start() {
    if (cfg_.channels.empty()) {
        std::cerr << "[!] channel list가 비어있어 ...\n";
        return;
    }
    if (running_.exchange(true)) return;        // 이미 실행 중이면 skip
    if (worker_.joinable()) worker_.join();     // 이전 worker가 남아있으면 정리
    worker_ = std::thread([this] { run(); });
}
```

### 단계별
1. **빈 채널 리스트 거부**: 순회할 게 없으면 시작 안 함
2. **중복 시작 방지**: `running_.exchange(true)`는 "기존 값 반환 + 새 값 설정"을 원자적으로. 이미 true면 `start()`가 두 번째 호출이라 그냥 return
3. **이전 worker 정리**: 이전에 worker가 자가 종료(연속 실패 등)했을 수 있음. 그러면 `worker_`는 joinable한 상태로 남아있음. 새 thread를 그냥 대입하면 **joinable thread에 대입 → `std::terminate` 호출**되어 프로세스가 죽습니다. 따라서 새로 만들기 전에 반드시 join
4. **새 thread 시작**: `run()` 메서드를 별도 스레드에서 실행

---

## 6. `stop()` 동작 — 워커 정지

```cpp
void ChannelHopper::stop() {
    running_.store(false);
    stopCv_.notify_all();                        // dwell 대기 중인 worker 즉시 깨움
    if (worker_.joinable()) worker_.join();
}
```

### 단계별
1. **종료 신호**: `running_=false`로 표시
2. **wakeup**: worker가 dwell 대기 중일 수 있으니 cv로 즉시 깨움. 이 한 줄이 없으면 worker는 dwell time(500ms) 다 기다린 후에야 종료 신호를 확인
3. **join**: worker가 실제로 종료할 때까지 대기. `joinable()` 체크는 worker가 안 떠 있을 수도 있는 경우(start() 안 했거나 이미 자가 종료) 방어

### 왜 destructor에서도 호출?
```cpp
~ChannelHopper() { stop(); }
```
사용자가 `stop()`을 안 부르고 객체를 destroy하더라도, 자동으로 워커가 정리됩니다. **C++ RAII 패턴**.

---

## 7. `setChannel()` 동작 — 실제 채널 변경

```cpp
bool ChannelHopper::setChannel(int channel) {
    char chBuf[16];
    std::snprintf(chBuf, sizeof(chBuf), "%d", channel);    // ① fork 전에 변환

    pid_t pid = fork();                                     // ② 자식 프로세스 분기
    if (pid < 0) return false;

    if (pid == 0) {
        ::execlp("iw", "iw", "dev", iface_.c_str(), "set", "channel", chBuf,
                 static_cast<char*>(nullptr));              // ③ 자식에서 iw 실행
        ::_exit(127);                                       // ④ exec 실패 시 종료
    }

    int status = 0;
    if (::waitpid(pid, &status, 0) < 0) return false;      // ⑤ 부모는 자식 종료 대기
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
```

### 단계별 해설

**① snprintf를 fork 이전에**
`fork()`로 자식이 만들어진 후, 자식에서는 **async-signal-safe 함수만** 호출해야 합니다 (POSIX 규칙). `snprintf`는 내부적으로 locale을 참조하므로 async-signal-safe가 **아닙니다**. 따라서 fork 이전에 미리 변환해두고, 자식은 그 결과(`chBuf`)를 그대로 사용합니다. fork는 메모리를 copy-on-write로 복사하므로 자식도 `chBuf`의 값을 볼 수 있습니다.

**② fork — 프로세스 복제**
`fork()`는 현재 프로세스를 그대로 복사한 자식 프로세스를 만듭니다. 부모는 자식의 pid를 받고, 자식은 0을 받습니다. 이를 이용해 분기.

**③ execlp — 자식을 iw 명령으로 교체**
`execlp("iw", "iw", "dev", ifname, "set", "channel", "11", nullptr)` 은 자식 프로세스의 메모리를 **`iw` 명령 실행 코드로 통째로 교체**합니다. `iw`가 채널 변경을 수행하고 종료합니다.

- 왜 `system("iw ...")` 안 쓰나? `system()`은 shell을 거치므로 인터페이스 이름에 `;` 같은 게 끼면 명령어 주입(shell injection) 가능. `execlp`는 인자를 그대로 넘기므로 안전.
- 마지막 인자의 `static_cast<char*>(nullptr)`는 variadic 함수에서 sentinel을 명시적으로 `char*`로 캐스팅 — 일부 플랫폼에서 `nullptr`만 넘기면 `int 0`으로 해석되어 ABI 차이가 생길 수 있기 때문.

**④ _exit(127) — execlp 실패 시 종료**
`iw`가 시스템에 없으면 `execlp`가 실패하고 그 다음 줄로 진행됩니다. `_exit(127)` 은 자식 프로세스를 즉시 종료. 127은 관례적으로 "command not found" 의미.

**⑤ waitpid — 자식 종료 대기**
부모는 자식이 끝날 때까지 기다립니다. `iw set channel 11`은 보통 수십 ms 안에 끝납니다. 자식의 종료 상태로 성공/실패 판단.

### 왜 `iw` 인가
Linux에서 monitor mode 어댑터의 채널을 바꾸는 표준 도구가 `iw`. 대안:
- `iwconfig`: deprecated
- netlink direct call: 복잡 (libnl 필요)
- ioctl SIOCSIWFREQ: deprecated (Wireless Extensions)

`iw`가 가장 간단하고 모든 distro에서 사용 가능.

---

## 8. `summary()` 동작 — 사람용 요약

```cpp
std::string ChannelHopper::summary() const;
// 출력 예: "2.4GHz(1,6,11) + 5GHz(36,40,44,48,149,153,157,161) — 500ms dwell"
```

채널을 2.4GHz/5GHz로 자동 분류(`ch <= 14` 휴리스틱)하여 사람이 읽기 좋게 출력. main.cpp의 시작 배너에서 인터페이스 이름과 함께 한 줄로 출력:

```cpp
std::cout << "[*] ";
if (adapters[i].label) std::cout << adapters[i].label << "-iface : ";
else                   std::cout << "interface     : ";
std::cout << adapters[i].ifname << " — " << hoppers[i]->summary() << "\n";
```

출력 예 (dual-adapter):
```
[*] fast-iface : mon0 — 2.4GHz(1,6,11) + 5GHz(36,40,44,48,149,153,157,161) — 200ms dwell
[*] dfs-iface  : mon1 — 5GHz(52,56,60,64,100,104,108,112,116,132,136,140) — 2000ms dwell
```

---

## 9. `run()` 동작 — 워커 스레드 본체 (가장 중요)

```cpp
void ChannelHopper::run() {
    constexpr int PER_CHANNEL_FAIL_LIMIT = 3;
    std::vector<int>  failures(cfg_.channels.size(), 0);
    std::vector<bool> skipped(cfg_.channels.size(), false);

    size_t idx = 0;
    while (running_.load()) {
        // ① 다음 동작 가능한 채널 찾기
        size_t scanned = 0;
        while (skipped[idx]) {
            idx = (idx + 1) % cfg_.channels.size();
            if (++scanned >= cfg_.channels.size()) {
                std::cerr << "[!] 모든 채널 영구 실패 — channel hopping 중단\n";
                running_.store(false);
                return;
            }
        }

        // ② 채널 변경 시도
        const int ch = cfg_.channels[idx];
        if (setChannel(ch)) {
            currentChannel_.store(ch);
            failures[idx] = 0;
        } else {
            failures[idx]++;
            if (failures[idx] == 1) {
                std::cerr << "[!] channel " << ch << " 변경 실패 ...\n";
            }
            if (failures[idx] >= PER_CHANNEL_FAIL_LIMIT) {
                skipped[idx] = true;
                std::cerr << "[!] channel " << ch << " 영구 skip (3회 실패)\n";
            }
        }

        // ③ dwell 만큼 대기 (stop 신호 오면 즉시 깨어남)
        {
            std::unique_lock<std::mutex> lock(stopMtx_);
            stopCv_.wait_for(lock, cfg_.dwell, [this] { return !running_.load(); });
        }

        idx = (idx + 1) % cfg_.channels.size();
    }
}
```

### 핵심 아이디어: 채널별 실패 추적

**문제 시나리오**: 2.4GHz-only 어댑터에서 5GHz 채널은 항상 실패합니다. 이전 정책("5회 연속 실패하면 전체 정지")이었다면, 첫 cycle에 5GHz 5개 채널이 연속 실패하자마자 호퍼 전체가 죽었습니다.

**해결**: 채널마다 독립적으로 실패 카운트. 같은 채널이 3회 실패하면 그 채널만 영구 skip. 나머지 채널은 계속 동작.

**시간 흐름** (2.4GHz-only 어댑터 기준):
- Cycle 1: ch 1, 6, 11 성공 + ch 36~161 (8개) 각 첫 실패 → `failures[3..10]=1`
- Cycle 2: 같은 채널들 각 두 번째 실패 → `failures[3..10]=2`
- Cycle 3: 세 번째 실패 → `skipped[3..10]=true`, 8개 영구 skip 로그
- Cycle 4 이후: ch 1, 6, 11만 순회

### ① 스킵된 채널 건너뛰기
```cpp
size_t scanned = 0;
while (skipped[idx]) {
    idx = (idx + 1) % cfg_.channels.size();
    if (++scanned >= cfg_.channels.size()) {
        // 한 바퀴 돌았는데 모두 skip → 전체 정지
    }
}
```

`scanned`는 "이번 라운드에서 skip 채널을 몇 번 건너뛰었나"를 세는 카운터. 한 바퀴 다 돌아도 활성 채널을 못 찾으면 (모두 skip), 호퍼 전체 정지.

### ② 채널 변경 결과 처리
- **성공**: `currentChannel_`을 atomic으로 갱신 (다른 스레드에서 조회 가능), 실패 카운트 리셋
- **실패**: 카운트 증가, 첫 실패 시에만 로그(스팸 방지), 임계치 도달 시 skip 표시

### ③ dwell 대기 — `condition_variable::wait_for`

```cpp
{
    std::unique_lock<std::mutex> lock(stopMtx_);
    stopCv_.wait_for(lock, cfg_.dwell, [this] { return !running_.load(); });
}
```

핵심: **dwell 시간만큼 자되, stop()이 오면 즉시 깨어남**.

옛날 코드는 `sleep_for(50ms)`로 10번 깨어나는 폴링 방식이었는데, OS 입장에서 비효율적이고 shutdown latency도 최대 50ms. 지금은:

- `wait_for(lock, dwell, predicate)`:
  - 최대 `dwell` 시간만큼 OS-level wait
  - `predicate`가 true가 되면 즉시 반환
  - `stop()`에서 `stopCv_.notify_all()` 부르면 잠 깨고 predicate 재평가 → `running_=false`니까 즉시 반환

- mutex(`stopMtx_`)는 공유 데이터 보호용이 아니라 **cv가 요구해서** 두는 것. cv 사용 시 반드시 lock과 함께 써야 함 (C++ 표준 규약).

### 매 run() 시작마다 fresh state
`failures`와 `skipped`는 `run()`의 지역 변수입니다. start()/stop()을 반복 호출하면 매번 새로 0으로 초기화됩니다. **이전에 skip된 채널도 다시 시도**합니다. 사용자가 권한을 고치고 재시작하는 시나리오를 지원하기 위함.

---

## 10. 전체 lifecycle 시나리오

### 시나리오 A: 정상 종료
```
main:    ChannelHopper hopper("mon0", {})
         hopper.start();              // running_=true, worker 시작
         ... pcap 캡처 ...
         (사용자 Ctrl+C)
         hopper.stop();
           ├ running_.store(false)
           ├ stopCv_.notify_all()     // worker가 wait_for에서 즉시 깨어남
           └ worker.join()            // worker 종료 대기

worker:  while (running_)
           setChannel(1) → 성공
           wait_for(500ms) [중단됨, predicate=false]
         loop exit
```

### 시나리오 B: 2.4GHz-only 어댑터
```
worker: cycle 1: ch 1 OK, ch 6 OK, ch 11 OK, ch 36..161 fail (각 failures=1)
        cycle 2: ch 1 OK, ..., ch 36..161 fail (각 failures=2)
        cycle 3: ch 1 OK, ..., ch 36..161 fail → skipped[3..10]=true, 영구 skip 로그
        cycle 4+: ch 1, 6, 11만 순회 (cycle = 1.5s, 다른 8개는 skip 큐로 점프)
```

### 시나리오 C: iw 미설치
```
worker: cycle 1: 모든 11개 채널 fail (failures=1)
        cycle 2: 모든 11개 fail (failures=2)
        cycle 3: 모든 11개 fail → skipped=[true]*11
        다음 iter: inner while가 한 바퀴 돌고 scanned==11 → "모든 채널 영구 실패" 로그, return
        worker 자가 종료.
        worker_는 joinable한 상태로 남음. destructor의 stop()이나 명시적 stop()이 join 처리.
```

### 시나리오 D: 듀얼 어댑터 운용 (fast + dfs)
```
main:    ChannelHopper fast("mon0", ChannelHopConfig::fastNonDfs())  // 11ch × 200ms
         ChannelHopper dfs("mon1",  ChannelHopConfig::dfsOnly())     // 12ch × 2000ms
         fast.start(); dfs.start();
         ... 두 worker thread 동시 동작 ...
         두 어댑터의 패킷이 공유 DeauthFloodDetector로 흘러감 (thread-safe)

fast worker:   200ms마다 ch={1,6,11,36,40,...} 순환 → 2.2초 / cycle
dfs worker:   2000ms마다 ch={52,56,60,64,100,...} 순환 → 24초 / cycle
```

각자 독립적으로 동작하지만 detector는 공유 → 통합 통계, alert에 채널 정보 포함되어 어느 어댑터에서 잡았는지 즉시 확인 가능 (예: `[fast][Deauth] ch=11`, `[dfs][Deauth] ch=100`).

---

## 11. 주의사항 / 한계

### 어댑터 의존
- 2.4GHz-only 어댑터(흔한 USB 보급형: AR9271 등): 5GHz 채널 자동으로 skip되어 동작
- monitor mode 미지원 드라이버: 전체 채널 fail → 호퍼 정지

### 권한
- `iw set channel`은 일반적으로 root 또는 CAP_NET_ADMIN 필요
- 권한 없으면 모든 채널 fail → 위와 같은 정지 시나리오

### Regulatory domain
- `iw reg get`로 확인. 국가별로 허용 채널이 다름
- 한국에서 5GHz UNII-3 (149+)은 보통 사용 가능. 일부 국가는 제한
- 허용되지 않은 채널은 fail로 분류되어 skip

### 6GHz 미지원
- `summary()`의 분류 로직은 `ch <= 14`이면 2.4GHz로 가정
- Wi-Fi 6E의 6GHz 채널 번호는 1-233이라 잘못 분류됨 — 6GHz 추가 시 freq 기반으로 개선 필요

### Capture gap during channel switch
- 채널 변경 자체는 수십 ms 걸림
- 그 사이 들어온 패킷은 못 봄 — 이건 모든 channel hopping 도구의 본질적 한계

---

## 12. 디버깅 체크리스트

증상별 대응:

| 증상 | 가능한 원인 | 확인 방법 |
|---|---|---|
| 시작 직후 "모든 채널 영구 실패" 로그 | iw 미설치 / 권한 부족 | `iw --version`, `sudo`로 재실행 |
| 일부 채널만 영구 skip | 어댑터가 해당 밴드 미지원 | `iw phy<n> info`로 지원 채널 확인 |
| 5GHz 채널 모두 fail | 어댑터 2.4GHz-only | `iw phy<n> info` |
| 캡처는 되는데 같은 BSSID만 보임 | 호퍼가 정지됨 | stderr 로그 확인, summary() 출력 확인 |
| 종료 시 hang | join 못함 | (자가 종료 시나리오) — 코드상 이미 처리됨, 문제 없어야 정상 |

---

## 13. 향후 확장 아이디어

코드 변경 없이 호출 측에서:
- 채널 목록만 바꾸기: `ChannelHopConfig{{1, 6, 11}, ...}` 으로 2.4GHz만
- dwell 조정: `cfg.dwell = std::chrono::milliseconds(200);`

코드 변경 필요:
- `iw phy<n> info` 파싱해서 지원 채널 자동 감지
- 채널별 dwell 가변화 (트래픽 많은 채널에 길게)
- 6GHz 지원 추가 (freq 기반 분류)
- ChannelHopper에 채널 변경 callback 추가 (변경 직후 어떤 동작 수행)
