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
- frame type
- SSID, BSSID, Source MAC, Destination MAC
- RSSI (radiotap)
- 캡처 채널 (radiotap)
- reason code (Deauth)

현재 BPF 필터는 **deauth만 캡처** — 다른 frame은 파싱 가능하지만 캡처 단계에서 걸러짐. 새 디텍터 추가 시 BPF 필터를 넓혀야 함.

### 2. Deauth Flood 탐지
- **Sliding window** (10초 기본): timestamp queue 기반
- **3-차원 카운터**:
  - `global` — 모든 deauth 합산 (raw rate, broadcast 공격 백스톱)
  - `perSrcMac` — 송신자 MAC별 (단일 attacker 식별)
  - `perBssid` — 표적 BSSID별 (MAC randomization 우회용, **가장 신뢰도 높은 신호**)
- **3-tier severity**: info / warn / critical
- **Reason code 필터**: 정상 disconnect(reason 3/8)는 perSrcMac/perBssid 카운터에서 제외 (false positive 감소). globalRate은 raw rate로 그대로 누적.
- **Escalation 인지 cooldown**: 같은 severity는 throttle(3초), 더 심각해지면 즉시 발사
- **Per-channel cooldown**: 채널별 독립 — 채널 hopping 중 다른 채널의 새 공격 놓치지 않음
- **Idle entry 자동 제거**: 5분간 활동 없는 srcMac/BSSID 정리 (메모리 누수 방지)
- **IDetector 인터페이스**: 새 탐지 모듈(Evil Twin, Rogue AP 등) 추가는 인터페이스 상속만으로 가능
- **Variant payload**: Alert는 카테고리별 타입 안전 payload (`std::variant`)
- **Thread-safe**: 듀얼 어댑터에서 두 capture thread가 안전하게 detector 공유

### 3. Channel Hopping
- 설정 가능한 채널 목록 + dwell time
- **2.4GHz + 5GHz non-DFS** 기본 (DFS 채널은 별도 어댑터 권장)
- 채널 변경: `iw dev <iface> set channel <n>` 를 `fork`/`execlp` 로 안전 호출 (shell injection 방지)
- **단순 순환 (실패는 다음 cycle에 재시도)**: 미지원 채널은 startup의 capability 필터(`iw phy info`)로 사전 제외 — hopper에 도달하는 채널은 모두 지원. 일시 실패는 다음 dwell cycle에 자동 재시도.
- **듀얼 어댑터 모드**: fast(non-DFS 빠른 sweep) + dfs(DFS 전담, 긴 dwell)
- **인터럽터블 dwell**: condition_variable로 stop() 호출 시 즉시 깨어남 (shutdown latency < 1ms)
- **bool 반환**: `start()`가 false면 channel list 비어 silent failure 없이 main에서 즉시 종료

---

## 아키텍처

```
              ┌─────────────────────────────┐
              │  pcap (radiotap, deauth만)   │
              └──────────────┬──────────────┘
                             │
                ┌────────────▼────────────┐
                │  parse_mgmt_frame()      │
                │  ParsedFrame 생성        │
                └────────────┬─────────────┘
                             │
              ┌──────────────▼──────────────┐
              │  capture_loop dispatcher     │
              │  vector<IDetector> 순회      │
              └──────────────┬──────────────┘
                             │
       ┌─────────────────────┼─────────────────────┐
       ▼                     ▼                     ▼
┌──────────────┐    ┌──────────────────┐   ┌──────────────┐
│DeauthFlood   │    │ (future)         │   │ (future)     │
│Detector      │    │ EvilTwinDetector │   │ RogueApDet.. │
└──────┬───────┘    └──────────────────┘   └──────────────┘
       │
       ▼
  ┌─────────┐
  │ Alert   │  AlertPayload = std::variant<DeauthFloodPayload, ...>
  └────┬────┘
       │
       ▼
┌──────────────────────┐
│ format_alert()       │  std::visit + if constexpr 디스패치
│ print_alert()        │  새 payload 누락 시 컴파일 에러로 catch
└──────────────────────┘
```

새 탐지 모듈 추가는 **3개 지점**만 손대면 됨:
1. `IDetector` 상속 + `observe()` 구현
2. `AlertPayload` variant에 새 payload 타입 추가
3. `format_alert` visit 분기 추가

---

## 요구 사항

- Linux (Ubuntu / Debian / Fedora / Arch)
- C++17 컴파일러 (g++ 9+, clang++ 10+)
- CMake 3.16+
- libpcap (개발 헤더)
- google-glog
- `iw` 명령 (채널 변경용)
- monitor mode 지원 무선 어댑터 (1개 또는 2개)
- (선택) GoogleTest — 단위 테스트 빌드용

---

## 의존성 설치

### Ubuntu / Debian
```bash
sudo apt update
sudo apt install build-essential cmake libpcap-dev libgoogle-glog-dev iw
sudo apt install libgtest-dev          # 선택, 테스트용
sudo apt install fonts-noto-cjk        # 선택, 터미널 한글 깨짐 방지
```

### Fedora / RHEL
```bash
sudo dnf install gcc-c++ cmake libpcap-devel glog-devel iw
sudo dnf install gtest-devel           # 선택
```

### Arch Linux
```bash
sudo pacman -S base-devel cmake libpcap google-glog iw
sudo pacman -S gtest                   # 선택
```

---

## 빌드

```bash
mkdir -p build
cd build
cmake ..
cmake --build . -j
```

빌드 결과:
- `build/wips-parser` — 메인 바이너리
- `build/wips-tests` — GoogleTest 설치 시 추가 생성

GoogleTest 미설치 시 "wips-tests 타겟 비활성" STATUS 메시지만 뜨고 메인 빌드는 정상 진행.

---

## 테스트

```bash
cd build && ctest --output-on-failure
```

현재 9개 단위 테스트:
- `SeverityFor` — tier 경계값 (info/warn/critical)
- `TrimWindow` — 슬라이딩 윈도우 cleanup, 경계 조건
- `Observe` — frameType 필터, payload 구조, cooldown, escalation
- `Observe.NormalDisconnectReasonSkipsPerSourceAndPerBssid` — reason 3/8 필터 검증
- `Observe.SuspiciousReasonCountsTowardsPerSource` — reason 7 정상 누적
- `Observe.PerBssidAlertCatchesMacRandomizedAttack` — MAC randomization 시나리오에서 perBssid가 잡아냄

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
어댑터 2개 역할 분담.

```bash
sudo ./wips-parser mon0 mon1
```
- `mon0` (fast): 2.4GHz + 5GHz non-DFS, 200ms dwell — 2.2초/cycle
- `mon1` (dfs):  5GHz DFS 전담, 2000ms dwell — 24초/cycle (CAC 비용 amortize)

### 옵션
```bash
sudo ./wips-parser --band 2g mon0          # 2.4GHz만
sudo ./wips-parser --band 5g mon0          # 5GHz non-DFS만
sudo ./wips-parser --channels 1,6,11 mon0  # 명시 채널만
```

**`sudo` 사용 시 LANG 손실로 한글 깨지면**: `sudo -E ./wips-parser mon0`

종료: `Ctrl+C`

---

## 출력 예시

### 시작 배너
```
[*] mode          : single-adapter
[*] interface     : mon0 — 2.4GHz(1,6,11) + 5GHz(36,40,44,48,149,153,157,161) — 500ms dwell
[*] deauth policy : window=10s, info/warn/critical thresholds:
[*]                 global    50/100/200
[*]                 perSrcMac 30/60/100
[*]                 perBssid  20/50/100 (가장 신뢰도 높은 신호)
[*]                 정상 disconnect(reason 3/8)는 perSrcMac/perBssid에서 제외
[*] 802.11 management frame 캡처 시작 ... (Ctrl+C to stop)
```

### Frame 캡처 + Alert
```
[Deauth]  src=DE:AD:BE:EF:00:01  dst=11:22:33:44:55:66  bssid=AA:BB:CC:DD:EE:FF  rssi=-30dBm  ch=11  reason=7
[ALERT deauth_flood INFO] deauth from DE:AD:BE:EF:00:01: 30 events in last 10000ms (total=30, ch=11, target=AA:BB:CC:DD:EE:FF, rssi=-30dBm, reason=7)
[ALERT deauth_flood INFO] deauth targeting AA:BB:CC:DD:EE:FF: 22 events in last 10000ms (total=22, ch=11, rssi=-30dBm, latest_reason=7)
[ALERT deauth_flood WARN] global deauth flood: 102 events in last 10000ms (latest: ch=11)
```

### Dual-adapter 라벨
```
[fast][Deauth] src=... ch=11
[dfs] [Beacon] src=... ch=100
```

---

## 디렉터리 구조

```
.
├── CMakeLists.txt
├── Readme.md
├── CLAUDE.md                             # Claude Code 프로젝트 지침
├── csa/                                  # 참고용 sub-project (CSA 공격 도구)
├── include/
│   ├── pch.h                             # precompiled header
│   ├── parser/                           # 802.11 파싱
│   │   ├── mac.h
│   │   ├── dot11.h
│   │   └── mgmt_parser.h
│   ├── detector/                         # 탐지 모듈
│   │   ├── alert.h                       #   Alert + AlertPayload variant
│   │   ├── i_detector.h                  #   IDetector 추상 인터페이스
│   │   └── deauth_detector.h
│   ├── hopper/                           # 채널 호핑
│   │   └── channel_hopper.h
│   ├── capture/                          # pcap 핸들 + capture loop
│   │   └── capture.h
│   ├── runtime/                          # CLI 파싱 + 시작 진단
│   │   └── startup.h
│   └── log/
│       └── console_log.h                 # format_alert/print_alert
└── src/
    ├── main.cpp                          # 시그널 + wiring만
    ├── parser/parser.cpp
    ├── detector/deauth_detector.cpp
    ├── hopper/channel_hopper.cpp
    ├── capture/capture.cpp
    └── runtime/startup.cpp
└── tests/
    └── test_deauth_detector.cpp          # GoogleTest 기반
```

`include/`와 `src/`가 모듈별 1:1 미러링.

---

## 핵심 타입

### `IDetector` — 모든 디텍터의 공통 인터페이스
```cpp
class IDetector {
public:
    virtual ~IDetector() = default;
    virtual const char* name() const = 0;
    virtual std::vector<Alert> observe(TimePoint timestamp, const ParsedFrame& frame) = 0;
};
```

새 디텍터 추가:
1. `IDetector` 상속 → `observe()` 구현. 관심 없는 `frameType`은 빈 vector 반환.
2. `main.cpp`에서 `detectors.push_back(std::make_unique<YourDetector>())`
3. (필요 시) `AlertPayload` variant에 새 payload 타입 추가
4. (필요 시) `format_alert` visit 분기 + `categoryName` 분기 추가
5. (필요 시) BPF 필터 넓히기 (`capture.cpp::open_monitor`)

### `Alert` — 데이터 전용
```cpp
struct Alert {
    AlertSeverity      severity;
    TimePoint          ts;
    std::optional<int> channel;
    AlertPayload       payload;
};

using AlertPayload = std::variant<DeauthFloodPayload>;
// 향후: std::variant<DeauthFloodPayload, EvilTwinPayload, RogueApPayload>
```

### `DeauthFloodPayload`
```cpp
struct DeauthFloodPayload {
    AlertScope                scope;        // globalRate | perSrcMac | perBssid
    std::optional<Mac>        srcMac;       // perSrcMac
    std::optional<Mac>        bssid;        // perBssid + perSrcMac context
    std::optional<int8_t>     rssi;         // perSrcMac/perBssid 최근 RSSI
    size_t                    count;
    std::chrono::milliseconds window;
    uint64_t                  total = 0;
    std::optional<uint16_t>   reasonCode;
};
```

### `ParsedFrame` — 디텍터 입력
```cpp
struct ParsedFrame {
    Dot11MgmtSubtype frameType;
    Mac              src, dst, bssid;
    std::optional<std::string> ssid;
    std::optional<int8_t>      rssi;
    std::optional<uint16_t>    reasonCode;
    std::optional<int>         channel;
};
```

디텍터별 이벤트 구조체를 따로 만들지 않고 `ParsedFrame`을 공통 입력으로 사용 — N×M 변환 코드 폭증 방지.

---

## 탐지 정책 기본값

### Window / Threshold
| 항목 | 기본값 |
|---|---|
| Sliding window | 10초 |
| globalRate info / warn / critical | 50 / 100 / 200 |
| perSrcMac info / warn / critical | 30 / 60 / 100 |
| perBssid info / warn / critical | 20 / 50 / 100 |
| Alert cooldown | 3초 |
| Idle srcMac/BSSID 제거 임계 | 5분 |
| Idle 스캔 주기 | 30초 (throttle) |

### Reason code 처리
| reason | 의미 | 처리 |
|---|---|---|
| 3 | STA leaving (deauth) | perSrcMac/perBssid 카운터 **제외** |
| 8 | STA leaving (disassoc) | perSrcMac/perBssid 카운터 **제외** |
| 1, 4, 5, 6, 7, 기타 | suspicious (또는 알 수 없음) | 정상 누적 |
| nullopt | reason 없음 | 의심으로 간주 → 누적 |

global 카운터는 모든 deauth 누적 (raw rate 가시성, broadcast 공격 backstop).

### Channel list 기본값
**Single-adapter** (`ChannelHopConfig{}`): 11채널 × 500ms = 5.5초 cycle
```
2.4GHz : 1, 6, 11
5GHz   : 36, 40, 44, 48, 149, 153, 157, 161   (non-DFS)
```

**Dual-adapter** (`fastNonDfs()` + `dfsOnly()`):
- fast: 위와 동일 11채널 × 200ms = 2.2초 cycle
- dfs:  `52, 56, 60, 64, 100, 104, 108, 112, 116, 132, 136, 140` × 2000ms = 24초 cycle

---

## 디버깅 / 트러블슈팅

| 증상 | 원인 / 확인 |
|---|---|
| `pcap_open_live` 실패 | root 권한 필요. `sudo` 로 실행 |
| `DLT != IEEE802_11_RADIO` | monitor mode 미설정 |
| `channel N 변경 실패` 로그 | `iw` 일시 거부 또는 일시 장애. 다음 dwell cycle에 자동 재시도. 영구 미지원이면 startup capability 필터에서 사전 제거됨 |
| 한글이 박스/물음표 (`tofu`) | 터미널 폰트에 CJK 없음 → `sudo apt install fonts-noto-cjk` |
| 한글이 깨진 라틴 문자 | sudo가 LANG 손실 → `sudo -E` 사용 또는 `sudo LANG=ko_KR.UTF-8` |
| Deauth는 많은데 alert 없음 | 임계치(perSrcMac 30, perBssid 20)에 못 미치거나 reason=3/8 (정상 disconnect로 분류됨) |
| `[ALERT]` 한 번 뜨고 안 뜸 | cooldown 3초 작동 중. escalation(info→warn) 시 즉시 발사 |
| `[Deauth]` burst 패턴 | 채널 호핑이 공격 채널을 떠난 사이 누적 후 한 번에 캡처 (정상) |
| 핸드폰 toggle만 했는데 critical | 임계치 너무 낮으면 발생 — 현재 기본값(50/100/200)으로는 거의 없음. 더 조이려면 생성자 인자로 조정 |
| 메모리 사용량 계속 증가 | 활성 srcMac/BSSID가 누적되면 정상. 5분 안 보인 entry는 자동 제거 |
| `채널 호퍼 시작 실패` 로그 후 종료 | `config_.channels`가 비어 있음 → `--channels` 옵션 또는 기본 프리셋 확인 |

---

## 한계 / 알려진 사항

- **Reason 우회**: 공격자가 reason=3/8로 deauth 보내면 perSrcMac/perBssid에서 제외됨. 단, 시중 도구(aircrack-ng suite 등) 대부분 reason=7을 사용해서 실용 우회는 드묾.
- **MAC randomization 부분적 우회 가능**: 매번 다른 src MAC 쓰면 perSrcMac 우회. perBssid 카운터가 backstop.
- **MAC spoofing**: 공격자가 AP의 MAC(globally unique)을 사칭하면 src로는 정상 AP와 구분 불가. RSSI/sequence number 기반 추가 검증이 향후 과제.
- **Channel hopping 캡처 갭**: 채널 변경 자체에 수십 ms 소요 — 그 사이 들어온 패킷은 못 봄 (모든 channel hopping 도구의 본질적 한계).
- **Regulatory domain 의존**: 일부 채널은 국가별 제한. `iw reg get` 으로 확인.
- **endianness 가정**: little-endian 호스트 가정 (대부분의 x86/ARM 환경에 해당).
- **6GHz Wi-Fi 6E 미지원**: 현재 채널 분류는 2.4/5GHz만.
- **POSIX 전용**: `fork`/`execlp`/`waitpid` 사용 — Windows 미지원 (WSL은 동작).
- **iw hang 가능성**: 드라이버 버그로 `iw set channel`이 행 걸리면 `hopper.stop()`이 무한 대기. 단, shutdown 순서가 `pcap_breakloop` → `threads.join` → `hopper.stop`이라 capture는 정상 종료.

---

## 향후 확장 아이디어

| 영역 | 항목 |
|---|---|
| Detection 정교화 | MAC U/L 비트로 randomized client 식별, RSSI 분산 기반 spoofing 판단, sequence number 분석, beacon 캡처로 BSSID baseline 학습 |
| 신규 디텍터 | Evil Twin (BSSID whitelist), Rogue AP, Beacon flood, Karma/Probe spoofing, Auth/Assoc flood |
| Alert 출력 | JSON 출력, Slack/Discord webhook, SIEM 통합 (syslog RFC 5424), 영구 기록 (SQLite) |
| Hopper | `iw` → NL80211 netlink 직접 호출 (성능 + iw hang 회피), 6GHz 지원 |
| 통합 | Detector→Hopper coordination (alert 시 해당 채널에 더 오래 머물기), critical alert 시 자동 counter-deauth |
| 운용 | Sensor ID, GPS 위치, OTA 업데이트, Prometheus `/metrics` 엔드포인트 |
| 보안 | root 강하 (CAP_NET_RAW/CAP_NET_ADMIN만 남기기), 로그 마스킹 (GDPR 등) |
| 설정 | YAML/TOML config + SIGHUP reload, MAC OUI 라벨링, Trusted BSSID whitelist |

---

## 라이선스

(프로젝트 상황에 맞게 추가)
