# 코드 보고서 — 쉽게 풀어쓴 가이드

이 프로그램은 **와이파이 공격(Deauth Flood)을 잡아내는 감시 프로그램**이에요.
프레임 파서(패킷을 뜯어보는 부분)는 빼고, 나머지 4개 파일을 쉽게 설명할게요.

대상 파일:
- `src/detector/deauth_detector.cpp` — 공격 탐지기
- `src/hopper/channel_hopper.cpp` — 채널 돌리기
- `src/runtime/startup.cpp` — 시작 준비
- `src/runtime/subprocess.cpp` — 외부 명령 실행 공통 헬퍼
- `src/main.cpp` — 전체 조립

---

## 이 프로그램이 하는 일

와이파이에는 "**deauth 프레임**"이라는 게 있어요.
원래는 "이제 와이파이 끊을게요~" 하고 정중하게 인사하는 메시지인데,
나쁜 사람이 이걸 가짜로 마구 보내서 **남의 와이파이를 강제로 끊을 수 있어요**.

이 프로그램은:
1. **여러 채널을 돌아다니면서** 와이파이 신호를 엿듣고
2. deauth 메시지가 **너무 많이 나타나면 경보를 울려요**.

비유하자면, 학교에서 누가 "**다들 집에 가!**"라고 자꾸 외치면 이상하잖아요?
그걸 감시하는 선생님 같은 프로그램이에요.

---

## 1. `deauth_detector.cpp` — 공격 탐지기

### 핵심 아이디어: "최근 10초 동안 몇 번 일어났지?"

deauth 메시지가 올 때마다 **시계 큐**에 시각을 적어 놔요.

```
시각이 적힌 큐 (deque):
┌──────┬──────┬──────┬──────┬──────┐
│ 0초  │ 2초  │ 5초  │ 7초  │ 9초  │
└──────┴──────┴──────┴──────┴──────┘
     ↑                              ↑
   오래된 것                      최신
```

지금이 11초라면, "최근 10초"는 1초~11초 구간이에요.
**0초는 너무 옛날**이니까 큐에서 빼버려요.

```
시각이 적힌 큐 (deque) — 0초는 제거됨:
┌──────┬──────┬──────┬──────┐
│ 2초  │ 5초  │ 7초  │ 9초  │   ← 큐 길이 = 4번 발생
└──────┴──────┴──────┴──────┘
```

이게 **슬라이딩 윈도우(sliding window)** 라는 거예요.
창문이 시간을 따라 움직이는 것 같다고 해서 그렇게 불러요.

코드로는 이렇게 생겼어요:

```cpp
using Window = std::deque<TimePoint>;

void trimWindow(Window& q, TimePoint cutoff) {
    while (!q.empty() && q.front() < cutoff) q.pop_front();
    // 큐 맨 앞이 너무 옛날이면 버려요. 시간 순으로 정렬돼 있으니 앞에서만 버리면 됨.
}
```

### 신호등처럼 3단계 경보 (severity)

경보는 **세기에 따라 3단계**예요.

| 단계 | 의미 | 비유 |
|---|---|---|
| `info` | 좀 많네? | 노란불 |
| `warn` | 의심스러워! | 주황불 |
| `critical` | 진짜 공격이야!! | 빨간불 |

세는 방식은 **3가지**:

1. **전체(globalRate)** — 그냥 deauth가 전체적으로 몇 번 일어났는지
2. **누가 보냈는지(perSrcMac)** — A라는 사람이 몇 번 보냈는지
3. **누구한테 보냈는지(perBssid)** — B라는 와이파이를 몇 번 공격했는지

왜 3가지로 나누냐면, 나쁜 사람이 **자기 이름(MAC 주소)을 자꾸 바꿔도**
"B 와이파이를 공격하는 횟수"는 그대로 잡히니까요.

### 신호등이 바뀔 때만 알림 (단계 상승 알림)

경보가 매 프레임마다 100번 떠도 사람은 한 번만 알면 되잖아요.
그래서 **신호등이 바뀔 때만 알림을 보내요**.

신호등이 노란불에서 계속 노란불이면 알림 안 보내고,
**노란불 → 주황불 → 빨간불처럼 더 심해질 때만** 새로 알림을 보내요.

규칙은 딱 2개:

1. **단계가 올라가면 알림** (없음→info, info→warn, warn→critical)
2. **공격이 멈춰서 count가 info 미만으로 떨어지면 리셋** — 다음에 다시 올라오면 새 알림

```cpp
bool isUpwardTransition(std::optional<AlertSeverity> last, AlertSeverity current) {
    if (!last.has_value()) return true;            // 처음이면 무조건 알림
    return current > last.value();                  // 단계가 올라갔을 때만 알림
}
```

흐름 예시:

```
시간 ──→
count:  3        5        4        2        1        0        3
         │        │                                            │
         ▼        ▼                                            ▼
       info     warn    (변화 없음 — 알림 X)              info (리셋 후 재진입)
       알림!    알림!                                       알림!
```

**타이머로 "3초 동안 알림 막기"** 같은 건 안 써요. 단계가 그대로면 어차피 알릴 게 없으니까요.
공격이 멈추면 자동으로 리셋되고, 다시 시작하면 알림이 또 나가요.

> 참고: 이 방식의 정식 이름은 **edge-triggered**(엣지 트리거)예요.
> 전기 회로에서 "신호 값이 바뀌는 순간(edge)에만 반응"하는 데서 온 용어입니다.

### 정상 disconnect는 빼기 (reason 3, 8)

핸드폰을 끄거나 와이파이를 일부러 끌 때도 deauth가 발생해요.
그런 정상 종료는 **reason 코드 3번이나 8번**으로 표시돼요.
이런 건 공격이 아니니까 카운트에서 빼요.

```cpp
if (isNormalDisconnect(frame.reasonCode)) return {};
// reason이 3이나 8이면 그냥 무시
```

### 너무 오래된 기록은 청소 (5분) — 왜 필요한가?

5분 동안 한 번도 안 보인 MAC 주소는 메모리에서 지워요.

**왜 필요해?** 진짜 공격자는 **MAC 주소를 매번 바꿔서** deauth를 쏘는 경우가 많아요
(MAC randomization). 그러면 unique MAC이 **수천 개** 쌓일 수 있어요.
센서가 24시간 돌아가면 map이 끝없이 커져서 결국 메모리가 터져요.

그래서 "5분 동안 조용했던 MAC은 잊어버리기"로 자동 청소해요.
30초마다 한 번씩만 청소 검사를 해서(throttle) 성능 부담도 적어요.

```cpp
if (lastRun.has_value() && (now - lastRun.value()) < interval) return;
// 30초 안 지났으면 그냥 return — 매번 검사하면 느려짐
```

---

## 2. `channel_hopper.cpp` — 채널 돌리기

### 왜 채널을 돌리나?

와이파이 채널은 **1번, 6번, 11번, 36번...** 이렇게 여러 개 있어요.
TV처럼 한 번에 한 채널만 들을 수 있어요.

그래서 1번 채널만 듣고 있으면 6번 채널에서 일어나는 공격은 못 봐요.
**라디오 채널 돌리듯이 빙글빙글 돌면서 들어야** 다 잡을 수 있어요.

```
1번 채널 (500ms 듣기) → 6번 채널 (500ms 듣기) → 11번 채널 (500ms 듣기)
        ↑                                                ↓
        └────────────────── 다시 1번 ──────────────────┘
```

이걸 **채널 호핑(hopping = 폴짝폴짝 뛰기)** 이라고 해요.

코드 본체는 정말 단순한 무한 루프예요:

```cpp
void ChannelHopper::run() {
    size_t idx = 0;
    while (running_.load()) {
        setChannel(config_.channels[idx]);   // 채널 바꾸고
        sleepOrUntilStop(config_.dwell);     // 500ms 기다리고
        idx = (idx + 1) % config_.channels.size();  // 다음 채널로
    }
}
```

### 채널을 어떻게 바꿔?

리눅스에는 `iw`라는 명령어가 있어요. 터미널에 이렇게 치면 채널이 바뀌어요:

```
iw dev mon0 set channel 6
```

C++ 프로그램에서 이 명령어를 **다른 프로세스로 실행**해서 채널을 바꿔요.

### 자식 프로세스를 부르는 방법 (fork + exec)

> 💡 이 fork/exec/pipe 패턴은 채널 호퍼, startup의 진단·capability 조회 등
> **여러 곳에서 똑같이 필요**해요. 그래서 `subprocess.cpp`에 **하나로 모았어요** —
> 자세한 건 아래 [5번 섹션](#5-subprocesscpp--외부-명령-실행-공통-헬퍼) 참고.
> 여기선 "이런 식으로 돌아간다"는 **원리만** 설명할게요.

비유로 설명하면:

- **fork()**: 나(부모)를 그대로 복사한 쌍둥이(자식)를 만들어요
- **exec()**: 그 쌍둥이가 옷을 갈아입고 다른 사람이 돼요 (= 다른 프로그램이 됨)

```
[ 부모 프로그램 ]
       │
       │ fork()
       ↓
[ 부모 ]  [ 자식 (똑같은 복사본) ]
   │             │
   │             │ execlp("iw", ...)
   │             ↓
   │       [ 자식이 iw 프로그램으로 변신! ]
   │             │
   │             │ iw가 채널 바꾸고 끝남
   │             ↓
   │       [ 자식 종료 ]
   │
   │ waitpid()로 자식 끝날 때까지 기다림
```

### 파이프(pipe) — 자식이 한 말을 부모가 듣기

`iw`가 실패하면 **에러 메시지(stderr)** 를 출력해요.
근데 자식 프로그램이 출력한 걸 부모가 어떻게 듣지?

**파이프**를 써요. 파이프는 **두 프로그램 사이의 종이컵 전화기** 같은 거예요.

```
┌─── 파이프 (종이컵 전화기) ───┐
│                                 │
[부모]                          [자식 (iw)]
 듣는 쪽 ←─────────────── 말하는 쪽
```

**실제 채널 호퍼 코드는 이제 이렇게 짧아요** (subprocess 헬퍼 덕분):

```cpp
bool ChannelHopper::setChannel(int channel) {
    SubprocessOpts opts; opts.captureStderr = true;
    auto r = run_subprocess({"iw", "dev", iface_, "set", "channel",
                             std::to_string(channel)}, opts);
    if (r.succeeded()) return true;
    LOG(ERROR) << "[iw] 채널 " << channel << " 변경 실패"
               << " | stderr: " << r.stderrText;
    return false;
}
```

옛날엔 이 함수가 **60줄**이었어요 (pipe, fork, dup2, read 루프, waitpid 다 손수). 지금은 **10줄**.

### 왜 그냥 `system("iw ...")` 안 쓰고 복잡하게 fork/exec?

`system()`은 편하지만 **shell을 거쳐서 위험**해요.
나쁜 입력이 들어오면 해킹당할 수 있어요 (shell injection).
`fork + exec`는 직접 실행해서 안전해요.

### 멈출 때 빨리 멈추기

500ms 잠자는 동안 Ctrl+C 눌렀는데도 500ms 다 기다린 다음에 멈추면 답답하잖아요.
그래서 **condition_variable**이라는 깨우는 알람을 써요.

```cpp
void sleepOrUntilStop(std::chrono::milliseconds dur) {
    stopCv_.wait_for(lock, dur, [this] { return !running_.load(); });
    // 500ms 자거나, 누가 깨우면 바로 깨어남
}
```

`stop()`이 불리면 `stopCv_.notify_all()`로 즉시 깨워줘요.

### LOG와 VLOG의 차이 — "공지방송"과 "라디오 채널"

코드를 보면 `LOG(INFO)`, `LOG(ERROR)` 말고 **`VLOG(1)`** 이라는 게 나와요.

```cpp
VLOG(1) << "[hopper] 채널 전환 성공: " << ch;   // channel_hopper.cpp:139
```

이건 **glog 라이브러리의 "조용한 로그"** 예요.

| 종류 | 항상 나옴? | 비유 |
|---|---|---|
| `LOG(INFO)` / `LOG(WARNING)` / `LOG(ERROR)` | ✅ 항상 | 학교 **공지방송** — 모두 들어야 함 |
| `VLOG(1)`, `VLOG(2)`, ... | ⚙️ 옵션 켰을 때만 | **라디오 채널** — 듣고 싶을 때만 켜기 |

`VLOG(N)`은 **숫자가 작을수록 중요**해요. 프로그램 시작할 때
"verbose level 몇까지 보여줄래?" 정해놓고, 그 숫자보다 같거나 작은 VLOG만 출력해요.

`main.cpp:53`에서 이렇게 정해놨어요:

```cpp
FLAGS_v = 1;   // VLOG(1)까지만 출력. VLOG(2)는 안 보임.
```

#### 왜 채널 전환 성공은 VLOG로 했어?

채널은 **500ms마다 한 번씩** 바뀌어요. 1시간이면 **7,200줄**!
이걸 다 `LOG(INFO)`로 띄우면 화면이 도배돼서 **진짜 중요한 alert가 묻혀요**.

그래서 **성공 로그는 조용히(VLOG), 실패 로그는 시끄럽게(`LOG(WARNING)`)** 분리한 거예요.

```cpp
if (setChannel(ch)) {
    VLOG(1) << "[hopper] 채널 전환 성공: " << ch;     // 디버깅할 때만 켜기
} else {
    LOG(WARNING) << "[hopper] 채널 " << ch << " 변경 실패";  // 항상 보여줌
}
```

평소엔 안 보이다가, 채널 호핑이 이상하면 `FLAGS_v` 올려서 보면 돼요.

---

## 3. `startup.cpp` — 시작 준비

이건 본격적인 일을 하기 전 **준비 운동** 같은 거예요.

### 하는 일 3가지

1. **사용법 출력** (`print_usage`)
   ```
   wips-parser [--band 2g|5g|all] [--channels 1,6,11] <iface>
   ```

2. **CLI 인자 파싱** (`parse_channel_list`)
   - `"1,6,11"` 같은 문자열을 받아서 `[1, 6, 11]` 숫자 리스트로 바꿔요.
   - 이상한 채널 번호(예: 99)는 거절해요.

3. **사전 진단** (`run_startup_diagnostics`)
   - **root 권한 있어?** 없으면 종료
   - **iw 명령어 설치돼 있어?** 없으면 종료

### 어댑터가 지원하는 채널만 골라내기

내 와이파이 카드가 5GHz를 못 받는데 5GHz 채널 돌리면 매번 실패해서 로그가 시끄러워요.
그래서 시작할 때 `iw phy info` 명령으로 **카드가 진짜 지원하는 채널 목록**을 알아내요.

```cpp
auto supported = querySupportedChannels(a.ifname);
// supported = [1, 2, ..., 11, 36, 40, 44, 48] 같은 리스트
// 이 안에 없는 채널은 자동으로 제외
```

---

## 5. `subprocess.cpp` — 외부 명령 실행 공통 헬퍼

### 왜 이 파일이 생겼나?

`iw` 명령을 부르는 곳이 **3군데**나 있었어요:

1. `channel_hopper.cpp::setChannel` — 채널 바꾸기 (`iw dev mon0 set channel 6`)
2. `startup.cpp::captureIwStdout` — 지원 채널 조회 (`iw phy phy0 info`)
3. `startup.cpp::exec_silent` — iw 설치 확인 (`iw --version`)

세 곳 다 **fork + dup2 + execvp + read + waitpid** 패턴이 거의 똑같아요.
같은 코드가 3번 복사돼 있으면:
- 버그 하나 고치려면 3군데 다 고쳐야 함
- 새로 추가할 때 또 복사할 가능성

그래서 **하나로 합쳤어요**. 이게 `run_subprocess()` 함수예요.

### 사용법 — 3가지 시나리오

```cpp
// 1) stderr만 캡처 — channel_hopper에서 iw 실패 메시지 받기
SubprocessOpts opts; opts.captureStderr = true;
auto r = run_subprocess({"iw", "dev", "mon0", "set", "channel", "6"}, opts);
if (r.succeeded()) { ... } else { LOG(ERROR) << r.stderrText; }

// 2) stdout 캡처 — iw phy info 결과 받기
SubprocessOpts opts; opts.captureStdout = true;
auto r = run_subprocess({"iw", "phy", "phy0", "info"}, opts);
std::string output = r.succeeded() ? r.stdoutText : "";

// 3) 캡처 없음 — 그냥 실행 성공/실패만 알면 됨
bool ok = run_subprocess({"iw", "--version"}).succeeded();
```

### 내부 동작 — 한 그림으로

```
부모 프로그램                       자식 프로그램 (예: iw)
─────────────────                  ─────────────────────

1. pipe() — 종이컵 전화기 만들기
                                    
2. fork() ───────────────────────► 쌍둥이 탄생
                                    
3. (부모는) 자식 끝나길 기다림      4. dup2() — stdout/stderr를
   read()로 메시지 듣기                종이컵 쓰는 쪽에 연결
                                    5. execvp("iw", ...) — iw로 변신
                                    6. iw가 일하다가 stdout/stderr에 출력
                                       → 부모가 read()로 받음
                                    7. iw 종료
                                    
8. waitpid() — 종료 코드 확인
9. SubprocessResult로 정리해서 반환
```

### "두 컵 동시에 듣기" — poll() 다중화

만약 자식이 stdout 1MB + stderr 1MB 쏟아내는데 부모가 stdout만 읽고 있으면?
**stderr 종이컵이 가득 차서 자식이 멈춰버려요** (write가 block). 그러면 부모는 영원히 자식을 기다리고 → **데드락!**

해결: **poll() 시스템 콜**로 "둘 중 아무 컵이라도 메시지 오면 알려줘" 라고 부탁해요.

```cpp
struct pollfd fds[2] = {
    {outPipe[0], POLLIN, 0},   // stdout 컵 듣기
    {errPipe[0], POLLIN, 0},   // stderr 컵 듣기
};
while (active > 0) {
    poll(fds, nfds, -1);   // 메시지 올 때까지 잠
    // 메시지 온 컵에서 read() — 둘 다 안 막힘
}
```

이게 옛날 코드보다 **더 안전**해진 부분이에요.

### 안전장치 — 캡처 상한

자식이 무한히 출력하면 부모 메모리도 무한히 늘어나요. 그래서 **4KB 상한**:

```cpp
struct SubprocessOpts {
    size_t maxCaptureBytes = 4096;   // 그 이상은 그냥 버림
};
```

`iw`는 출력이 짧으니까 충분해요.

### `SubprocessResult` — 결과 모음

```cpp
struct SubprocessResult {
    bool        spawned;       // fork 자체 성공?
    bool        exited;        // 정상 종료? (시그널로 죽으면 false)
    int         exitCode;      // 0이면 성공
    std::string stdoutText;
    std::string stderrText;
    
    bool succeeded() const { return spawned && exited && exitCode == 0; }
};
```

호출자는 보통 `r.succeeded()` 한 줄로 충분하고, 실패 시 `r.stderrText`로 이유 확인.

---

## 4. `main.cpp` — 전체 조립

이 파일은 모든 부품을 **조립하는 설명서**예요.

> 💡 CLI 파싱, 어댑터 셋업, 배너 출력 같은 잡일은 `startup.cpp`에 빠져있어서
> `main()`은 정말 **위에서 아래로** 읽으면 무슨 일이 일어나는지 한눈에 보여요.

### 진행 순서

```
1. 로그/시그널 준비
   ↓
2. 명령어 인자 읽기 (--band, --channels, mon0 등)
   ↓
3. 사전 진단 (root? iw 있어?)
   ↓
4. 어댑터별 채널 필터링 (지원 채널만 남기기)
   ↓
5. pcap 핸들 열기 (와이파이 엿듣기 시작)
   ↓
6. 탐지기(DeauthFloodDetector) 만들기
   ↓
7. 채널 호퍼(ChannelHopper) 시작
   ↓
8. 캡처 스레드 시작 (와이파이 패킷 받으면서 탐지)
   ↓
9. Ctrl+C 누를 때까지 기다림
   ↓
10. 종료 정리
```

### Ctrl+C 처리 — self-pipe 패턴

Ctrl+C를 누르면 시그널이라는 게 발생해요.
**시그널 핸들러 안에서는 거의 아무것도 못 해요** (안전한 함수가 몇 개 안 됨).

그래서 **자기한테 파이프로 1바이트 쪽지를 보내는** 트릭을 써요.

```cpp
static int g_signal_pipe[2];

static void on_sigint(int) {
    g_running.store(false);                // "이제 끝낼 시간!" 깃발 내림
    ::write(g_signal_pipe[1], "x", 1);     // 파이프에 1바이트 톡!
}

// main 스레드는 파이프 읽으면서 자고 있다가, 1바이트 오면 깨어남
static void wait_for_shutdown_signal() {
    char buf;
    ::read(g_signal_pipe[0], &buf, 1);   // 1바이트 올 때까지 잠
}
```

이렇게 하면 Ctrl+C 누르는 순간 main이 즉시 깨어나서 종료 절차를 시작해요.

### RAII — "다 쓰면 자동으로 정리"

C++의 멋진 기능이에요. **변수가 사라질 때 자동으로 청소**해줘요.

```cpp
using PcapPtr = std::unique_ptr<pcap_t, decltype(&pcap_close)>;

std::vector<PcapPtr> pcaps;
PcapPtr p(open_monitor(a.ifname), &pcap_close);
// 'p'가 사라지는 순간 자동으로 pcap_close(p)가 불려요!
```

장난감 갖고 놀다가 **상자에 넣으면 자동으로 정리되는 마법 상자** 같은 거예요.
중간에 에러로 `return 1` 해도 누수 없이 정리돼요.

### 종료 순서가 중요해요

```cpp
1. pcap_breakloop(p)   // "캡처 그만!" 깃발 (즉시 반환)
2. threads.join()       // 캡처 스레드 종료 기다림
3. hoppers stop()       // 채널 호퍼 정지 (iw가 안 끝나면 무한 대기 위험!)
4. pcaps.clear()        // pcap 핸들 닫기
```

만약 3번을 먼저 하면, **iw가 멈추는 동안 캡처 스레드도 못 끝나서 데드락**이 생길 수 있어요.
그래서 캡처를 먼저 깔끔히 정리하고, hopper는 나중에 처리해요.

---

## 전체 데이터 흐름

```
[와이파이 신호 (공기 중)]
        ↓
[리눅스 커널 + 드라이버]
        ↓
[pcap_next_ex() — 패킷 한 개 받기]
        ↓
[parser — 패킷 해석] ←── (이 보고서에서는 생략)
        ↓
[ParsedFrame — 누가, 어디로, 왜 보냈는지]
        ↓
[DeauthFloodDetector::observe() — 슬라이딩 윈도우에 기록]
        ↓
[임계치 넘으면 → Alert 만들기]
        ↓
[화면에 빨갛게 출력!]


[동시에 별도 스레드에서]
ChannelHopper → 500ms마다 iw 명령으로 채널 변경
            → 1 → 6 → 11 → 36 → 40 → ... → 다시 1
```

---

## 핵심 C++ 개념 요약

| 개념 | 한 줄 설명 |
|---|---|
| `namespace` | 이름이 겹치지 않게 묶어두는 폴더 같은 것 |
| `anonymous namespace` | 이름 없는 폴더 — 이 파일에서만 보임 |
| `std::deque` | 양쪽 끝에서 빨리 넣고 빼는 줄 (큐) |
| `std::unique_ptr` | "나만 가진 포인터" — 사라질 때 자동 정리 (RAII) |
| `std::mutex` | 화장실 열쇠 — 한 명만 들어갈 수 있음 (스레드 안전) |
| `std::condition_variable` | 알람시계 — 자고 있다가 누가 깨우면 일어남 |
| `fork()` | 내 복사본(쌍둥이) 만들기 |
| `exec()` | 다른 프로그램으로 변신 |
| `pipe()` | 두 프로세스 사이 종이컵 전화기 |
| `signal` | Ctrl+C 같은 운영체제의 메시지 |
| `LOG(...)` | glog의 "공지방송" — 항상 출력 (INFO/WARNING/ERROR) |
| `VLOG(N)` | glog의 "라디오 채널" — `FLAGS_v` 켰을 때만 출력 (디버그용) |

---

## 새 탐지기 추가하는 법 (`IDetector` 인터페이스)

지금은 deauth flood 하나만 탐지하지만, 나중에 **Evil Twin**(가짜 와이파이 AP),
**Beacon Flood**(가짜 와이파이 도배) 같은 다른 공격도 잡고 싶을 수 있어요.

그럴 때를 위해 `include/detector/i_detector.h`라는 **공통 약속(인터페이스)** 이 있어요.

### IDetector가 뭔가?

이건 "**모든 탐지기는 이렇게 생겨야 해!**" 하는 규칙이에요. 딱 한 줄짜리 약속이에요:

```cpp
class IDetector {
public:
    virtual ~IDetector() = default;
    virtual std::vector<Alert> observe(TimePoint timestamp, const ParsedFrame& frame) = 0;
};
```

해석:
- "프레임 하나 줄게(`observe`), 알림 리스트로 돌려줘"
- 관심 없는 프레임이면 빈 리스트(`{}`)를 반환하면 돼요
- 같은 인터페이스를 따르면 `main.cpp`가 **모두에게 똑같이 프레임을 뿌려줘요**

### 3단계로 새 탐지기 추가하기

#### 1단계: 새 클래스 만들기

```cpp
// include/detector/evil_twin_detector.h
#include "i_detector.h"

class EvilTwinDetector : public IDetector {
public:
    std::vector<Alert> observe(TimePoint ts, const ParsedFrame& frame) override;
private:
    std::mutex mutex_;   // 멀티스레드 안전을 위해 필수
    // ... 필요한 상태(예: 본 BSSID들의 SSID 매핑)
};
```

#### 2단계: `observe()` 구현하기

```cpp
// src/detector/evil_twin_detector.cpp
std::vector<Alert> EvilTwinDetector::observe(TimePoint ts, const ParsedFrame& frame) {
    if (frame.frameType != MGMT_SUBTYPE_BEACON) return {};  // 관심 없는 프레임은 패스

    std::lock_guard<std::mutex> lock(mutex_);
    // ... 탐지 로직 ...
    return alerts;
}
```

**중요한 규칙 3가지:**
- ✅ **관심 없는 frameType은 즉시 `return {}`** — 모든 디텍터가 모든 프레임을 받으니까요
- ✅ **mutex로 thread-safe 보장** — 듀얼 어댑터면 캡처 스레드가 2개라 동시 호출돼요
- ✅ **timestamp는 절대 자기가 만들지 마요** — 받은 `ts`를 그대로 써야 모든 디텍터 시간선이 맞아요

#### 3단계: `main.cpp`에 등록

```cpp
// main.cpp — 이 한 줄만 추가
detectors.push_back(std::make_unique<EvilTwinDetector>());
```

이게 **끝**이에요. 캡처 스레드가 알아서 모든 디텍터에 프레임을 뿌려요.

### Alert 모양 바꾸기 (좀 더 어려운 경우)

새 탐지기가 deauth와 **다른 정보**를 알리고 싶으면 어떡하지?

지금은 `Alert.payload`가 `DeauthFloodPayload` 하나만 갖고 있어요:

```cpp
struct Alert {
    AlertSeverity         severity;
    std::optional<int>    channel;
    DeauthFloodPayload    payload;   // ← 지금은 한 종류만
};
```

새 payload(예: `EvilTwinPayload`)를 추가하려면 `std::variant`로 바꿔야 해요:

```cpp
using AlertPayload = std::variant<DeauthFloodPayload, EvilTwinPayload>;
struct Alert {
    AlertSeverity         severity;
    std::optional<int>    channel;
    AlertPayload          payload;
};
```

그리고 출력 코드(`console_log`)도 `std::visit`로 어떤 종류인지 분기해야 해요.
`include/detector/alert.h` 주석에 이 얘기가 적혀 있어요.

### 빌드 시스템에 추가

새 `.cpp` 파일은 `CMakeLists.txt`에 등록해줘야 해요:

```cmake
add_executable(wips-parser
    src/main.cpp
    src/detector/deauth_detector.cpp
    src/detector/evil_twin_detector.cpp   # ← 추가
    # ...
)
```

---

## 디버깅 가이드

| 증상 | 의심 위치 |
|---|---|
| 캡처는 되는데 경보 안 떠 | reason 3/8 정상 disconnect로 필터됐을 가능성 |
| 경보 한 번 뜨고 조용해 | 단계가 그대로면 재발사 안 함 — 더 심해져야(warn/critical) 다시 나옴 |
| 채널이 안 바뀌네 | `iw` 실패 — `[iw] 채널 N 변경 실패 \| stderr: ...` 로그에서 진짜 이유 확인 (subprocess가 자식 stderr 잡아줌) |
| 외부 명령이 hang | `subprocess.cpp::run_subprocess`의 `waitpid` — 자식 프로세스가 stuck. ps로 확인 |
| 시작하자마자 FATAL | root 권한 없거나 iw 미설치 |
| Ctrl+C가 안 먹어 | signal pipe 생성 실패 가능성 |
