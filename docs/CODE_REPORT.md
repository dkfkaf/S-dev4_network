# 코드 보고서 — src/ 주요 파일 해설

본 문서는 wips-parser의 핵심 4개 소스 파일을 한 곳에 모은 가이드입니다.
파일 단위 흐름, 클래스/함수 책임, 등장하는 C++ 개념(namespace, pipe 등)을 같이 풀어 적었습니다.

대상 파일:
- `src/detector/deauth_detector.cpp`
- `src/hopper/channel_hopper.cpp`
- `src/runtime/startup.cpp`
- `src/main.cpp`

---

## 사전 개념

### 1. `namespace`란?

C++의 **namespace**는 "이름 공간" — 함수/변수/클래스 이름들이 충돌하지 않도록 묶어 두는 그룹입니다.

#### 일반 namespace
```cpp
namespace audio {
    void play();
}
namespace video {
    void play();   // audio::play와 충돌 안 함 — 같은 이름 다른 공간
}
audio::play();
video::play();
```
가장 흔한 예: `std::` — 표준 라이브러리가 사는 namespace. `std::vector`, `std::cout` 등.

#### Anonymous namespace (이 프로젝트에서 자주 등장)
```cpp
namespace {
    bool helperFunction() { ... }
}
```
이름이 없는 namespace. 안에 든 것들은 **그 .cpp 파일 안에서만 보임** — 다른 .cpp가 import해도 못 봄.

**왜 쓰나**:
- 헤더에 노출하기 싫은 내부 헬퍼를 둘 때
- 다른 파일과 함수 이름이 충돌해도 안전 (내부에 격리됨)
- C 언어의 `static` 키워드와 비슷한 역할이지만 C++ 모던 스타일

**프로젝트 안 실제 사용처**:
- `deauth_detector.cpp`의 `isNormalDisconnect()` — 이 파일 안에서만 쓰는 헬퍼
- `startup.cpp`의 `valid_channel_set()`, `exec_silent()` — 외부에 노출 안 함

```cpp
// startup.cpp
namespace {
    const std::vector<int>& valid_channel_set() { ... }
    bool exec_silent(...) { ... }
}  // namespace
// → 다른 .cpp에서 valid_channel_set 호출 불가, 같은 이름 다른 함수 충돌 안 함
```

### 2. `errPipe`란?

`channel_hopper.cpp::setChannel`에 나오는 `errPipe[2]`는 **자식 프로세스의 표준 에러(stderr)를 부모가 읽어오기 위한 Unix pipe**입니다.

#### Pipe 기본
- Unix pipe = 두 프로세스 사이의 단방향 byte stream
- `int fds[2]; pipe(fds);` 호출하면:
  - `fds[0]`: **읽기 전용 끝** (read end)
  - `fds[1]`: **쓰기 전용 끝** (write end)
- 누군가 `fds[1]`에 쓰면 다른 누군가가 `fds[0]`에서 읽을 수 있음

#### 왜 필요한가
`channel_hopper`는 `iw dev mon0 set channel 6` 같은 명령을 외부 프로세스로 실행합니다. `iw`가 실패하면 stderr에 에러 메시지를 출력하는데, 그 메시지를 **부모(wips-parser) 로그로 가져오고 싶음**.

해결: pipe로 자식의 stderr를 부모가 받기.

#### 흐름

```
[ 부모 (wips-parser) ]                       [ 자식 (iw) ]
                                               
1. pipe(errPipe) 호출                          
   errPipe[0] = 읽기 끝                       
   errPipe[1] = 쓰기 끝                       
                                               
2. fork() ──────────────────────────────────► 자식 생성
                                               (errPipe 양쪽 끝 둘 다 상속됨)
                                               
3. errPipe[1] close (안 씀)              3. errPipe[0] close (안 씀)
                                          4. dup2(errPipe[1], STDERR_FILENO)
                                             — 자식의 stderr를 pipe write로 연결
                                          5. errPipe[1] close (이미 stderr로 복사됨)
                                          6. execlp("iw", ...) — iw 실행
                                             iw가 stderr에 쓰는 모든 것이 pipe로 감
                                             
4. errPipe[0]에서 read()                  
   자식이 stderr에 쓴 내용을 받음            
                                               
5. waitpid(자식)                          7. iw 종료
   exit code 확인                             
                                               
6. 실패 시 captured 문자열을 LOG(ERROR)로 출력
```

#### 코드 매핑
```cpp
// channel_hopper.cpp:39-44 — pipe 생성
int errPipe[2] = {-1, -1};
if (::pipe(errPipe) != 0) {
    LOG(ERROR) << "[iw] pipe() 실패: " << ...;
    return false;
}

// channel_hopper.cpp:53-60 — 자식 측: stderr를 pipe write로 리다이렉트
if (pid == 0) {
    ::close(errPipe[0]);                   // 자식은 읽기 끝 안 씀
    /*dup2가 머임?*/
    ::dup2(errPipe[1], STDERR_FILENO);     // stderr → pipe[1]
    ::close(errPipe[1]);                   // 원본 디스크립터 닫기
    ::execlp("iw", "iw", "dev", iface_.c_str(), ...);
    ::_exit(127);                          // exec 실패 시
}

// channel_hopper.cpp:62-80 — 부모 측: read 끝에서 stderr 내용 읽기
::close(errPipe[1]);                       // 부모는 쓰기 끝 안 씀
std::string captured;
for (;;) {
    ssize_t n = ::read(errPipe[0], buf, sizeof(buf));
    if (n > 0) captured.append(buf, n);
    else break;
}
::close(errPipe[0]);

// channel_hopper.cpp:88-97 — 실패 시 출력
if (!ok) {
    LOG(ERROR) << "[iw] 채널 " << channel << " 변경 실패"
               << " | stderr: " << captured;
}
```

**핵심 패턴**: fork/exec 시 자식 프로세스 출력을 부모가 받으려면 pipe + dup2 콤보. POSIX 프로그래밍의 정석.

---

## 파일별 해설

### A. `src/detector/deauth_detector.cpp`

Deauth Flood 탐지 모듈의 본체. `IDetector` 인터페이스를 구현하고 슬라이딩 윈도우 기반 카운터 3개(globalRate, perSrcMac, perBssid)를 운영합니다.

#### 구조 개관

```
1. anonymous namespace
   └─ isNormalDisconnect()           reason 3/8 필터 헬퍼

2. ctor                               window/threshold/cooldown/idleTimeout 초기화

3. 정적 유틸 (public)
   ├─ trimWindow()                   윈도우 밖 timestamp 제거
   └─ severityFor()                  count → AlertSeverity 매핑

/*source는 좀 명칭이 비 직관적인데*/
4. private 헬퍼
   ├─ shouldAlert()                   cooldown + escalation 판정
   ├─ forgetIdleSrcMacs()             5분 안 보인 srcMac 제거
   └─ forgetIdleBssids()              동일, BSSID 차원

5. 스냅샷 조회 (외부 모니터링용)
   ├─ globalCount()
   ├─ trackedSrcMacs() / trackedBssids()
   ├─ statsFor() / bssidStatsFor()
   └─ policySummary()                 현재 설정된 정책을 한 줄로

6. observe()                          IDetector::observe 구현 — 핵심 진입점

/*cooldown이 필요한가?*/
7. process 함수
   ├─ processGlobalEvent()            전역 raw rate 카운터 + 단일 cooldown
   ├─ processPerSrcMacEvent()         srcMac별 카운터 + 그 srcMac의 cooldown
   └─ processPerBssidEvent()          BSSID별 카운터 + 그 BSSID의 cooldown
```

#### observe() 흐름

```cpp
std::vector<Alert> observe(TimePoint timestamp, const ParsedFrame& frame) {
    if (frame.frameType != MGMT_SUBTYPE_DEAUTH) return {};   // 1
    
    std::lock_guard<std::mutex> lock(mutex_);                // 2
    
    const TimePoint now = globalEvents_.empty()
        ? timestamp
        : std::max(timestamp, globalEvents_.back());         // 3
    const TimePoint cutoff = now - window_;                  // 4
    
    processGlobalEvent(frame, now, cutoff, alerts);          // 5
    
    if (!isNormalDisconnect(frame.reasonCode)) {             // 6
        processPerSrcMacEvent(frame, now, cutoff, alerts);
        processPerBssidEvent (frame, now, cutoff, alerts);
    }
    
    forgetIdleSrcMacs(now);
    forgetIdleBssids(now);                                   // 7
    return alerts;
}
```

1. **frameType 필터**: deauth 아니면 즉시 return — IDetector의 dumb broadcast 모델 대응
2. **Lock**: 듀얼 어댑터에서 두 capture thread가 동시 진입할 수 있어서 mutex로 직렬화
3. **시간 단조성 보장**: 두 thread의 timestamp가 미세하게 역전될 수 있음. 큐가 시간 순으로 정렬돼야 trimWindow가 정상 동작 → max로 clamp
4. **cutoff**: 윈도우의 가장 오래된 허용 시각 (= now - window_)
5. **global 처리**: 항상 누적 (raw rate 가시성)
6. **reason 필터**: reason 3/8(정상 disconnect)는 perSrcMac/perBssid 누적 제외 — false positive 감소
7. **Idle cleanup**: 5분 안 보인 srcMac/BSSID 제거 (메모리 관리)

#### 슬라이딩 윈도우 == timestamp queue

```cpp
using Window = std::deque<TimePoint>;
```

- 이벤트마다 `push_back(now)`
- `trimWindow(q, cutoff)`로 `front`가 cutoff보다 옛날이면 `pop_front`
- 큐 크기(size())가 윈도우 내 이벤트 수
- amortized O(1) — 정렬 가정 활용 (앞쪽=옛날, 뒤쪽=최신)

#### Cooldown + Escalation

```cpp
bool shouldAlert(const CooldownState& state, AlertSeverity currentSeverity, TimePoint now) {
    if (!state.lastAlert.has_value()) return true;                 // 첫 alert
    if (currentSeverity > state.lastAlertSeverity.value()) return true;  // escalation
    return (now - state.lastAlert.value()) >= cooldown_;           // cooldown 지났는지
}
```

- 첫 alert: 무조건 발사
- info → warn처럼 severity가 올라가면 cooldown 무시하고 즉시 발사
- 같거나 낮은 severity는 cooldown(3초) 적용

#### Anonymous namespace 사용

```cpp
namespace {
bool isNormalDisconnect(std::optional<uint16_t> reason) {
    if (!reason.has_value()) return false;
    return reason.value() == 3 || reason.value() == 8;
}
}  // namespace
```

`isNormalDisconnect`는 이 .cpp 안에서만 쓰는 헬퍼라 anonymous namespace에 격리. 헤더에 노출 안 됨 → 다른 파일이 의존할 수 없어 깔끔.

---

### B. `src/hopper/channel_hopper.cpp`

채널 호퍼 — 인터페이스의 채널을 주기적으로 바꿔 전 대역 스캔. `iw` 외부 명령을 fork/exec로 호출. 미지원 채널은 startup의 capability 필터에서 사전 제거됨.

#### 구조 개관

```
1. ctor / dtor                       iface 저장, dtor에서 stop() 자동 호출

2. start() → bool                    worker thread 생성 (false면 config.channels 비어 있음)

3. stop()                            running_=false, cv 신호, worker join

4. currentChannel()                  현재 채널 (atomic int 읽기)

5. setChannel(int) → bool            iw 외부 호출 + stderr 캡처 (errPipe 사용)

6. sleepOrUntilStop(dur)             cv로 dur 또는 stop 신호까지 sleep

7. summary()                         "2.4GHz(1,6,11) + 5GHz(36,...) — 500ms dwell" 형식

8. run()                             worker thread 본체 — 단순 순환 루프
```

#### run() — 단순 순환 루프

```cpp
void ChannelHopper::run() {
    size_t idx = 0;
    while (running_.load()) {
        const int ch = config_.channels[idx];
        if (setChannel(ch)) {
            currentChannel_.store(ch);
        } else {
            currentChannel_.store(-1);
            LOG(WARNING) << "[hopper] 채널 " << ch << " 변경 실패 — 다음 cycle에 자동 재시도";
        }
        sleepOrUntilStop(config_.dwell);
        idx = (idx + 1) % config_.channels.size();
    }
}
```

**과거의 복잡한 retry 로직 제거**: 이전엔 채널별 failure 카운터 + 지수 retry delay (1s → 2s → ... → 5분 cap) + "모두 지연 중" sleep 처리가 있었음. 이유는 미지원 채널을 영구 skip 안 하면서도 일시 장애 복구 허용. 현재는 startup의 `querySupportedChannels`가 미지원 채널을 사전 제거하므로, 여기 도달하는 채널은 모두 지원. 일시 실패는 단순히 다음 cycle에 재시도하면 충분 — 별도 state 관리 불필요.

#### setChannel() — fork + execlp + errPipe

상세는 위 [errPipe 설명](#2-errpipe란) 참고. 요약:
1. pipe로 stderr 캡처 채널 마련
2. fork — 자식은 stderr를 pipe로 redirect 후 `iw dev <iface> set channel <N>` exec
3. 부모는 자식의 stderr를 읽어두고 waitpid로 종료 코드 확인
4. 실패 시 캡처된 stderr를 LOG(ERROR)로 출력

**왜 system() 안 쓰고 fork/execlp?**
- `system("iw ...")`는 shell을 거쳐서 shell injection 위험 (인자가 사용자 입력에서 오면 위험)
- fork + execlp는 shell 거치지 않고 직접 실행 — 더 안전, 빠름

#### Interruptible dwell (`sleepOrUntilStop`)

```cpp
void sleepOrUntilStop(std::chrono::milliseconds dur) {
    std::unique_lock<std::mutex> lock(stopMtx_);
    stopCv_.wait_for(lock, dur, [this] { return !running_.load(); });
}
```

`stop()`이 `stopCv_.notify_all()`을 부르면 즉시 깨어남. `std::this_thread::sleep_for()`만 쓰면 dwell이 만료될 때까지 못 멈춰서 shutdown 지연.

---

### C. `src/runtime/startup.cpp`

프로세스 시작 시점의 잡일들 — CLI 파싱, 사전 진단, 로그 디렉토리. main.cpp에서 분리해 wiring 코드와 잡일 코드를 격리.

#### 구조 개관

```
namespace {
    valid_channel_set()                  허용 채널 목록 (2.4GHz + 5GHz)
    exec_silent(prog, args)              외부 명령 silent 실행 (진단용)
}

print_usage()                            CLI 사용법 출력
parse_channel_list(csv, out)             "1,6,11" → vector<int> 파싱
run_startup_diagnostics()                root 권한 + iw 설치 확인
```

#### Anonymous namespace 사용 — 내부 헬퍼 격리

```cpp
namespace {
const std::vector<int>& valid_channel_set() { ... }
bool exec_silent(const char* prog, std::initializer_list<const char*> args) { ... }
}  // namespace
```

`valid_channel_set`은 `parse_channel_list` 내부에서만 쓰고, `exec_silent`는 `run_startup_diagnostics` 내부에서만 씀. 헤더에 노출할 이유가 없어서 anonymous namespace에 넣어 파일 내부 전용으로 만듦.

#### exec_silent — fork + execvp + /dev/null

```cpp
bool exec_silent(const char* prog, std::initializer_list<const char*> args) {
    pid_t pid = ::fork();
    if (pid == 0) {
        int devnull = ::open("/dev/null", O_WRONLY);
        ::dup2(devnull, STDOUT_FILENO);
        ::dup2(devnull, STDERR_FILENO);
        // ... argv 빌드
        ::execvp(prog, ...);
        ::_exit(127);
    }
    // 부모: waitpid + WIFEXITED 확인
}
```

`channel_hopper`의 setChannel과 유사하지만 stderr 캡처가 아니라 **버림** (/dev/null로 redirect). `iw --version`이 성공하는지만 알면 되니까 출력 내용은 필요 없음.

---

### D. `src/main.cpp`

전체 wiring. 시그널 처리 + CLI 인자 → 어댑터 셋업 → pcap 열기 → 디텍터/호퍼 생성 → 스레드 launch → shutdown.

#### 구조 개관

```
1. 글로벌 상태
   ├─ g_running (atomic bool)            shutdown 신호
   └─ g_signal_pipe[2]                   SIGINT를 main 스레드로 전달

2. 시그널 핸들러
   ├─ on_sigint()                        g_running=false + pipe write
   └─ wait_for_shutdown_signal()         pipe read로 main 블록

3. PcapPtr 타입
   └─ unique_ptr<pcap_t, decltype(&pcap_close)>

4. AdapterSetup 구조체                    {ifname, label, ChannelHopConfig}

5. main()
   ├─ 로그/시그널 파이프 초기화
   ├─ CLI 인자 파싱 (--band, --channels, positional ifname)
   ├─ run_startup_diagnostics()
   ├─ AdapterSetup 빌드
   ├─ pcap 핸들 오픈 (RAII)
   ├─ 디텍터/호퍼 생성
   ├─ 시작 배너 출력
   ├─ 시그널 핸들러 설치
   ├─ capture thread launch
   ├─ wait_for_shutdown_signal()         ← SIGINT까지 블록
   └─ shutdown
```

#### Signal pipe — self-pipe 패턴

```cpp
static std::atomic<bool> g_running(true);
static int               g_signal_pipe[2] = {-1, -1};

static void on_sigint(int) {
    g_running.store(false);
    const char x = 1;
    ssize_t n = ::write(g_signal_pipe[1], &x, 1);    // 시그널 안전 호출만
    (void)n;
}

static void wait_for_shutdown_signal() {
    char buf;
    for (;;) {
        ssize_t n = ::read(g_signal_pipe[0], &buf, 1);
        if (n > 0 || n == 0) return;
        if (errno != EINTR) return;
    }
}
```

**왜 pipe?** 시그널 핸들러에서 호출 가능한 함수는 매우 제한적(async-signal-safe). `cv.notify_all()` 같은 건 안 됨. 대신 pipe write는 안전 — `::write()`가 async-signal-safe. main 스레드는 그 pipe를 read로 블록하다가 깨어남. POSIX의 정석 self-pipe 패턴.

#### PcapPtr — RAII로 pcap_close 자동화

```cpp
using PcapPtr = std::unique_ptr<pcap_t, decltype(&pcap_close)>;

std::vector<PcapPtr> pcaps;
for (const auto& a : adapters) {
    PcapPtr p(open_monitor(a.ifname), &pcap_close);
    if (!p) return 1;                      // 이전 pcaps는 RAII로 정리
    pcaps.push_back(std::move(p));
}
```

`std::unique_ptr`의 두 번째 템플릿 인자가 **deleter 타입**. 보통 디폴트는 `std::default_delete<T>` (delete 호출)인데, 여기서는 함수 포인터 `decltype(&pcap_close)`를 deleter로 지정. 객체 소멸 시 `pcap_close(ptr)` 자동 호출.

**효과**:
- exit 경로(`return 1`)가 4군데 있어도 누수 없음 — vector destructor가 자동 정리
- 명시적 cleanup 루프 제거 → 코드 단순화

#### Shutdown 순서 — deadlock 회피

```cpp
for (auto& p : pcaps) pcap_breakloop(p.get());      // 1. capture 깨우기

for (auto& t : threads) t.join();                    // 2. capture 종료 대기
LOG(INFO) << "[shutdown] capture 스레드 종료 완료";

for (auto& h : hoppers) h->stop();                   // 3. hopper 정지 (iw hang 가능)
LOG(INFO) << "[shutdown] hopper 정지 완료";

pcaps.clear();                                        // 4. pcap 해제 (destructor)
LOG(INFO) << "[shutdown] pcap 핸들 해제 완료";
```

**중요**: `pcap_breakloop`는 non-blocking flag 설정만 함. capture 스레드는 그 flag 보고 다음 `pcap_next_ex`에서 break. `hopper.stop()`은 worker thread join을 포함해 **iw 행 시 무한 대기 가능**.

이전 순서(`hopper.stop()` 먼저 → `threads.join()`)는 iw hang 시 capture 스레드도 영원히 못 끝나는 문제. 현재 순서면 hopper가 hang해도 capture는 정상 종료되고 로그도 남음.

#### Detector dispatcher

```cpp
std::vector<std::unique_ptr<IDetector>> detectors;
detectors.push_back(std::make_unique<DeauthFloodDetector>());

threads.emplace_back([&, i] {
    capture_loop(pcaps[i].get(), adapters[i].label, detectors, g_running);
});
```

`capture_loop`는 모든 디텍터에 frame을 broadcast. 새 디텍터(예: EvilTwin) 추가 시 `detectors.push_back(make_unique<EvilTwinDetector>())` 한 줄만 추가하면 끝. dispatcher 손 안 댐.

---

## 파일 간 데이터 흐름

```
[ kernel/driver ] 
       │
       │  802.11 frame (radiotap-wrapped)
       ▼
[ pcap_next_ex ]
       │
       ▼
[ capture.cpp::capture_loop ]
       │
       │  pcap_pkthdr + uint8_t* pkt
       ▼
[ parser.cpp::parse_mgmt_frame ]
       │
       │  ParsedFrame (frameType, src, dst, bssid, rssi, channel, reasonCode)
       ▼
[ for each IDetector in detectors ]
       │
       │  observe(timestamp, frame)
       ▼
[ DeauthFloodDetector::observe ]
       │
       │  vector<Alert> (0~3개)
       ▼
[ console_log::format_alert / print_alert ]
       │
       │  std::visit → format_deauth_flood
       ▼
[ stdout + glog ]
```

병렬로:
```
[ ChannelHopper worker thread ]
       │
       │  매 dwell(500ms)마다 setChannel()
       ▼
[ iw dev mon0 set channel N ]
       │
       │  실패 시 errPipe로 stderr 캡처 → LOG
       │  실패 시 currentChannel = -1, 다음 cycle에 재시도
       ▼
[ wireless driver ]
```

main thread는 `wait_for_shutdown_signal()`에서 SIGINT 받을 때까지 잠들어 있고, 시그널 받으면 위 모든 흐름을 역순으로 종료.

---

## 디버깅 가이드

| 증상 | 어느 파일 / 함수 의심 |
|---|---|
| 캡처는 되는데 alert 안 뜸 | `deauth_detector.cpp::observe` — frame.reasonCode가 3/8이면 perSrcMac/perBssid 필터됨. global 임계치(50)에도 못 미치는지 확인 |
| Alert이 한 번 뜨고 멈춤 | `deauth_detector.cpp::shouldAlert` — cooldown 3초 작동 중. escalation까지 가야 다시 발사 |
| 채널이 한 곳에 멈춰 있음 | `channel_hopper.cpp::run` 단순 순환. setChannel 반복 실패 의심 — WARNING 로그 `[hopper] 채널 N 변경 실패` 빈도 확인 |
| `iw` 실패하는데 이유 모름 | `channel_hopper.cpp::setChannel` — errPipe로 캡처된 stderr가 LOG(ERROR)로 나옴 |
| 시작 시 LOG(FATAL) | `startup.cpp::run_startup_diagnostics` — root 권한 또는 iw 미설치 |
| Ctrl+C 안 먹힘 | `main.cpp::on_sigint` + `wait_for_shutdown_signal` — pipe 생성 실패했는지 확인 |
| 프로세스 끝났는데 핸들 남음 | `main.cpp::pcaps.clear()` 누락 — RAII에 의존하니 vector가 소멸해야 close 됨 |

---

## 더 알아보기

- IDetector 인터페이스 활용 — `include/detector/i_detector.h` 주석 참조
- Alert variant 디스패치 — `include/detector/alert.h`의 `AlertPayload` 정의
- 빌드 / 테스트 / 실행 — `Readme.md`
