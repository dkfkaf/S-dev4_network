# wips-parser

캡처한 raw 무선 패킷에서 **802.11 management frame을 파싱하고, Deauth Flood 공격을 탐지하며, 채널을 자동 순환**하는 C++17 Wireless IPS 프로젝트.

---

## 기능 요약

### 1. 802.11 Management frame 파싱
지원 frame type:
- Beacon
- Probe Request / Probe Response
- Authentication / Deauthentication
- Association Request / Association Response

각 프레임에서 추출:
- frame type (enum)
- SSID, BSSID, Source MAC, Destination MAC
- RSSI (radiotap)
- 캡처 채널 (radiotap)
- reason code (Deauth/Disassoc)

### 2. Deauth Flood 탐지
- **Sliding window** (10초 기본): timestamp queue 기반
- **이중 카운터**: 전역 + per-source MAC 병렬 운용
- **3-tier severity**: info / warn / critical (`SeverityTier` 묶음)
- **Escalation 인지 cooldown**: 같은 severity는 throttle, 더 심각해지면 즉시 발사
- **Per-channel cooldown**: 채널별 독립 cooldown — 채널 hopping 중 다른 채널의 새 공격 놓치지 않음
- **Idle source 자동 제거**: 5분간 활동 없는 source 정리 (메모리 누수 방지)
- **Alert는 데이터 전용 구조체**: 메시지 포맷팅은 consumer 책임 — 새 출력 형식(JSON/webhook 등) 추가 시 detector 손 안 댐
- **Thread-safe**: 듀얼 어댑터 운용 시 두 capture thread가 안전하게 detector 공유

### 3. Channel Hopping
- 설정 가능한 채널 목록 + dwell time (`NON_DFS_CHANNELS`, `DFS_CHANNELS` 상수)
- **2.4GHz + 5GHz non-DFS** 기본 (DFS 채널은 별도 어댑터 권장)
- 채널 변경: `iw dev <iface> set channel <n>` 을 `fork`/`execlp` 로 안전 호출 (shell injection 방지)
- **채널별 실패 추적**: 같은 채널 3회 실패 시 영구 skip — 2.4GHz-only 어댑터에서 5GHz 실패해도 호퍼 전체가 죽지 않음
- **듀얼 어댑터 모드**: fast(non-DFS 빠른 sweep) + dfs(DFS 전담, 긴 dwell)
- **인터럽터블 dwell**: condition_variable로 stop() 호출 시 즉시 깨어남 (shutdown latency < 1ms)

---

## 요구 사항

- Linux (Ubuntu / Debian / Fedora / Arch 등)
- C++17 컴파일러 (g++ 9+, clang++ 10+)
- CMake 3.16+
- libpcap (개발 헤더)
- `iw` 명령 (채널 변경용)
- monitor mode 지원 무선 어댑터 (1개 또는 2개)

---

## 의존성 설치

### Ubuntu / Debian
```bash
sudo apt update
sudo apt install build-essential cmake libpcap-dev iw
```

### Fedora / RHEL
```bash
sudo dnf install gcc-c++ cmake libpcap-devel iw
```

### Arch Linux
```bash
sudo pacman -S base-devel cmake libpcap iw
```

---

## 빌드

```bash
mkdir -p build
cd build
cmake ..
cmake --build . -j
```

빌드 결과: `build/wips-parser`

---

## Monitor mode 설정

radiotap 헤더(`DLT_IEEE802_11_RADIO`)가 붙은 패킷이 필요하므로 인터페이스를 monitor mode로 전환.

### iw 사용 (권장)
```bash
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
```

### airmon-ng 사용
```bash
sudo airmon-ng check kill
sudo airmon-ng start wlan0
# → wlan0mon 생성
```

---

## 실행

### Single-adapter 모드
어댑터 1개로 2.4GHz + 5GHz non-DFS 11채널 × 500ms 순환.

```bash
sudo ./wips-parser mon0
```

### Dual-adapter 모드
어댑터 2개 역할 분담 — 한쪽은 빠른 sweep, 다른쪽은 DFS 전담.

```bash
sudo ./wips-parser mon0 mon1
```
- `mon0` (fast): 2.4GHz + 5GHz non-DFS, 200ms dwell — 2.2초/cycle
- `mon1` (dfs):  5GHz DFS 전담, 2000ms dwell — 24초/cycle

종료: `Ctrl+C`

---

## 출력 예시

### Single-adapter
```
[*] mode          : single-adapter
[*] interface     : mon0 — 2.4GHz(1,6,11) + 5GHz(36,40,44,48,149,153,157,161) — 500ms dwell
[*] deauth window : 10s (info=10/warn=20/critical=40 global, 5/10/20 per-source)
[*] 802.11 management frame 캡처 시작 ... (Ctrl+C to stop)
[Beacon]   src=AA:BB:CC:DD:EE:FF  bssid=AA:BB:CC:DD:EE:FF  ssid="MyWiFi"  rssi=-42dBm  ch=6
[Deauth]   src=DE:AD:BE:EF:00:01  bssid=AA:BB:CC:DD:EE:FF  rssi=-30dBm  ch=11  reason=7
[ALERT INFO] deauth from DE:AD:BE:EF:00:01: 5 events in last 10000ms (total=5, latest: ch=11, reason=7)
[ALERT WARN] global deauth flood: 22 events in last 10000ms (latest: ch=11)
```

### Dual-adapter
```
[*] mode          : dual-adapter
[*] fast-iface : mon0 — 2.4GHz(1,6,11) + 5GHz(36,40,44,48,149,153,157,161) — 200ms dwell
[*] dfs-iface  : mon1 — 5GHz(52,56,60,64,100,104,108,112,116,132,136,140) — 2000ms dwell
[*] deauth window : 10s (info=10/warn=20/critical=40 global, 5/10/20 per-source)
[*] 802.11 management frame 캡처 시작 ... (Ctrl+C to stop)
[fast][Beacon] src=... ssid="OfficeWiFi" ch=6
[dfs][Beacon]  src=... ssid="Enterprise5G" ch=100
[fast][Deauth] src=... ch=11 reason=7
[ALERT CRITICAL] deauth from AA:BB:CC:DD:EE:FF: 25 events in last 10000ms (total=25, latest: ch=11, reason=7)
```

---

## 디렉터리 구조

```
.
├── CMakeLists.txt
├── Readme.md
├── CLAUDE.md                          # Claude Code 프로젝트 지침 (자동 로드)
├── csa/                               # 기존 CSA 구현 (참고용 sub-project)
├── docs/                              # 워크플로 역할 문서
│   ├── IMPLEMENTER.md
│   ├── REVIEWER.md
│   └── REVISER.md
├── help/                              # 모듈/학습 설명서
│   ├── channel_hopper.md              #   Channel hopping 상세
│   ├── deauth_detector.md             #   Deauth detector 상세
│   └── study_notes.md                 #   코드 학습 노트 (헷갈리는 부분 Q&A)
├── include/
│   ├── pch.h                          # precompiled header
│   ├── parser/                        # 802.11 파싱 모듈
│   │   ├── mac.h
│   │   ├── dot11.h
│   │   └── mgmt_parser.h
│   ├── detector/                      # Deauth flood 탐지 모듈
│   │   ├── alert.h                    #   Alert (데이터 전용) + TimePoint alias
│   │   └── deauth_detector.h
│   └── hopper/                        # 채널 호핑 모듈
│       └── channel_hopper.h           #   NON_DFS_CHANNELS / DFS_CHANNELS 상수
└── src/
    ├── main.cpp                       # 통합 진입점, format_alert (string 포맷팅)
    ├── parser/
    │   └── parser.cpp
    ├── detector/
    │   └── deauth_detector.cpp
    └── hopper/
        └── channel_hopper.cpp
```

`include/` 와 `src/` 가 모듈별로 1:1 미러링되어 모듈 단위 작업이 쉽습니다.

---

## 핵심 타입

### `Alert` — 데이터 전용
```cpp
struct Alert {
    AlertSeverity            severity;     // info / warn / critical
    AlertScope               scope;        // global vs perSource (의도 명시)
    TimePoint                ts;
    std::optional<Mac>       source;       // perSource인 경우만 set
    size_t                   count;        // 윈도우 내 이벤트 수
    std::chrono::milliseconds window;
    std::optional<int>       channel;
    std::optional<uint16_t>  reasonCode;   // perSource만 의미
    uint64_t                 total = 0;    // perSource 누적 (global은 0)
};
```
**메시지 포맷팅 책임은 consumer**. `main.cpp::format_alert()` 가 plaintext로 변환. 새 출력 (JSON/webhook 등) 추가 시 detector 손 안 댐.

### `DeauthEvent` — detector 입력
```cpp
struct DeauthEvent {
    TimePoint                ts;
    Mac                      src, dst, bssid;
    std::optional<int8_t>    rssi;
    std::optional<uint16_t>  reasonCode;
    std::optional<int>       channel;
};
```
**detector는 `ParsedFrame`을 모름**. `main.cpp::make_deauth_event()` 가 변환 — parser/detector 결합 분리.

---

## 탐지 정책 기본값

### Window / Threshold
| 항목 | 기본값 |
|---|---|
| Sliding window | 10초 |
| Global info / warn / critical | 10 / 20 / 40 events |
| Per-source info / warn / critical | 5 / 10 / 20 events |
| Alert cooldown | 3초 |
| Idle source 제거 임계 | 5분 |
| Idle 스캔 주기 | 30초 (throttle) |

### Channel list 기본값
**Single-adapter** (`ChannelHopConfig{}`): 11채널 × 500ms = 5.5초 cycle
```
2.4GHz : 1, 6, 11
5GHz   : 36, 40, 44, 48, 149, 153, 157, 161   (non-DFS)
```

**Dual-adapter** (`fastNonDfs()` + `dfsOnly()`):
- fast: 위와 동일 11채널 × 200ms = 2.2초 cycle
- dfs:  `52, 56, 60, 64, 100, 104, 108, 112, 116, 132, 136, 140` × 2000ms = 24초 cycle (CAC 비용 amortize)

---

## 상세 문서

| 문서 | 다루는 내용 |
|---|---|
| [`help/channel_hopper.md`](help/channel_hopper.md) | Channel hopping 모듈 상세 — fork/execlp, condition_variable, 채널별 실패 추적, 듀얼 어댑터 |
| [`help/deauth_detector.md`](help/deauth_detector.md) | Deauth detector 상세 — sliding window, cooldown + escalation, per-channel cooldown, idle source 제거 |
| [`help/study_notes.md`](help/study_notes.md) | 코드의 헷갈리는 부분 Q&A — mutex/cv 상호작용, iterator invalidation, std::pair, 시간 클램핑 등 |

---

## 디버깅 / 트러블슈팅

| 증상 | 원인 / 확인 |
|---|---|
| `pcap_open_live` 실패 | root 권한 필요. `sudo` 로 실행 |
| `DLT != IEEE802_11_RADIO` | monitor mode 미설정. 위의 monitor mode 섹션 참고 |
| `channel N 변경 실패` 로그 | `iw` 미설치, 또는 어댑터/드라이버 미지원. `iw phy phyN info` 로 지원 채널 확인 |
| 5GHz 채널만 모두 fail | 어댑터가 2.4GHz-only. 호퍼는 자동으로 2.4GHz만 순환 (per-channel skip 동작) |
| `모든 채널 영구 실패` 로그 | `iw` 미설치 또는 권한 부족. `iw --version`, `sudo` 재실행 |
| Deauth는 많은데 alert 없음 | window/threshold 매칭 실패. 기본값 기준 10초 내 10건 이상 필요 |
| `fast-iface와 dfs-iface는 달라야 합니다` | 듀얼 모드에서 같은 인터페이스 두 번 지정 |
| 한 번만 alert 뜨고 끝 | cooldown 작동 중 (3초). 3초 이상 기다리면 다시 발사 |
| 메모리 사용량 계속 증가 | 활성 source가 누적되면 정상. 5분 안 보인 source는 자동 제거됨 |

---

## 한계 / 알려진 사항

- **DFS 채널 진입 비용**: 드라이버에 따라 CAC(Channel Availability Check) 시간 필요. 듀얼 어댑터의 dfs 어댑터가 미지원이면 첫 cycle (~72초) 동안 dfs 입력 없음
- **Spoofing 부분 취약**: 공격자가 매번 src MAC 바꾸면 per-source 카운터 우회. 전역 카운터가 backstop
- **Channel hopping 캡처 갭**: 채널 변경 자체에 수십 ms 소요 — 그 사이 들어온 패킷은 못 봄 (모든 channel hopping 도구의 본질적 한계)
- **Regulatory domain 의존**: 일부 채널은 국가별 제한. `iw reg get` 으로 확인
- **endianness 가정**: little-endian 호스트 가정 (대부분의 x86/ARM 환경에 해당)
- **6GHz Wi-Fi 6E 미지원**: 현재 채널 분류는 2.4/5GHz만
- **테스트 미작성**: 핵심 로직(`shouldAlert` cooldown/escalation, `severityFor` boundary)에 unit test 부재. 향후 추가 권장
- **POSIX 전용**: `fork`/`execlp`/`waitpid` 사용 — Windows 미지원 (WSL은 동작)

---

## 향후 확장 아이디어

| 영역 | 항목 |
|---|---|
| Alert | JSON 출력, Slack/Discord webhook, rate-limiting, silent mode (whitelist) |
| Detection | BSSID 카운터 (spoofing 강건성), reason code 분포 분석, RSSI 위치 추정, adaptive threshold |
| Persistence | SQLite로 alert 영구 기록, 통계 evict 시 archive |
| Hopper | `iw phy info` 파싱해 지원 채널 자동 감지, 채널별 가변 dwell, 6GHz 지원 |
| 통합 | Detector→Hopper coordination (alert 시 해당 채널 더 오래 머물기), critical alert 시 자동 차단 룰 |

---

## 라이선스

(프로젝트 상황에 맞게 추가)
