# wips-parser

캡처한 raw 무선 패킷에서 **802.11 management frame을 파싱하고, Deauth Flood 공격을 탐지하며, 채널을 자동 순환**하는 C++17 Wireless IPS 프로젝트.

---

## 기능 요약

### 1. 802.11 Management frame parsing
지원하는 frame type:
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

### 2. Deauth Flood Detection
- **Sliding window** (10초 기본): timestamp queue 기반
- **이중 카운터**: 전역 + per-source MAC
- **3-tier severity**: info / warn / critical
- **Escalation 인지 cooldown**: 같은 severity는 throttle, 더 심각해지면 즉시 발사
- **Per-channel cooldown**: 채널별로 독립 cooldown (채널 hopping 중 다른 채널의 새 공격 놓치지 않음)
- **Idle source 자동 제거**: 활동 없는 source 자동 정리 (메모리 누수 방지)
- **Thread-safe**: 듀얼 어댑터 운용 시 두 capture thread가 안전하게 공유

### 3. Channel Hopping
- 설정 가능한 채널 목록 + dwell time
- **2.4GHz + 5GHz non-DFS** 기본 지원 (DFS 채널은 별도 어댑터 권장)
- 채널 변경: `iw dev <iface> set channel <n>` 을 `fork`/`execlp` 로 안전 호출
- **채널별 실패 추적**: 같은 채널 3회 실패 시 영구 skip — 2.4GHz-only 어댑터에서 5GHz 채널 실패해도 호퍼 전체가 죽지 않음
- **듀얼 어댑터 모드**: 한 어댑터는 빠른 sweep, 다른 어댑터는 DFS 전담

---

## 요구 사항

- Linux (Ubuntu / Debian / Fedora / Arch 등)
- C++17 컴파일러 (g++ 9+, clang++ 10+)
- CMake 3.16+
- libpcap (개발 헤더)
- `iw` 명령 (채널 변경용 — 보통 기본 설치)
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

radiotap 헤더(`DLT_IEEE802_11_RADIO`)가 붙은 패킷이 필요하므로 인터페이스를 monitor mode로 전환해야 한다.

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
# → wlan0mon 생성됨
```

---

## 실행

### Single-adapter 모드
어댑터 1개로 2.4GHz + 5GHz non-DFS 11채널을 500ms씩 순환.

```bash
sudo ./wips-parser mon0
```

### Dual-adapter 모드
어댑터 2개로 역할 분담 — 한쪽은 빠른 sweep, 다른쪽은 DFS 전담.

```bash
sudo ./wips-parser mon0 mon1
```
- `mon0` (fast): 2.4GHz + 5GHz non-DFS, 200ms dwell
- `mon1` (dfs):  5GHz DFS 전담, 2000ms dwell

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
[Deauth]   src=DE:AD:BE:EF:00:01  bssid=AA:BB:CC:DD:EE:FF  ssid=<n/a>     rssi=-30dBm  ch=11  reason=7
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
[ALERT CRITICAL] deauth from AA:BB:CC: 25 events in last 10000ms (total=25, latest: ch=11, reason=7)
```

---

## 디렉터리 구조

```
.
├── CMakeLists.txt
├── Readme.md
├── CLAUDE.md
├── csa/                            # 기존 CSA 구현 (참고용, 별도 sub-project)
├── help/                           # 모듈별 상세 설명서
│   ├── channel_hopper.md
│   └── deauth_detector.md
├── include/
│   ├── pch.h                       # precompiled header
│   ├── parser/                     # 802.11 파싱 모듈
│   │   ├── mac.h
│   │   ├── dot11.h
│   │   └── mgmt_parser.h
│   ├── detector/                   # Deauth flood 탐지 모듈
│   │   ├── alert.h
│   │   └── deauth_detector.h
│   └── hopper/                     # 채널 호핑 모듈
│       └── channel_hopper.h
└── src/
    ├── main.cpp
    ├── parser/
    │   └── parser.cpp
    ├── detector/
    │   └── deauth_detector.cpp
    └── hopper/
        └── channel_hopper.cpp
```

`include/` 와 `src/` 가 모듈별로 1:1 미러링되어 있어, 어떤 모듈을 작업하려면 해당 폴더만 보면 된다.

---

## 탐지 정책 기본값

### Window / Threshold
| 항목 | 기본값 |
|---|---|
| Sliding window | 10초 |
| Global info | 10 events |
| Global warn | 20 events |
| Global critical | 40 events |
| Per-source info | 5 events |
| Per-source warn | 10 events |
| Per-source critical | 20 events |
| Alert cooldown | 3초 |
| Idle source 제거 임계 | 5분 |

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

각 모듈의 동작 원리와 설계 결정은 `help/` 폴더 참조:

- [`help/channel_hopper.md`](help/channel_hopper.md) — Channel hopping 모듈 상세 (fork/execlp, condition_variable, 채널별 실패 추적, 듀얼 어댑터)
- [`help/deauth_detector.md`](help/deauth_detector.md) — Deauth flood detector 상세 (sliding window, cooldown + escalation, per-channel cooldown, idle source 제거)

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
| `fast-iface와 dfs-iface는 달라야 합니다` | 듀얼 모드에서 같은 인터페이스 두 번 지정. 다른 어댑터 사용 |

---

## 한계 / 알려진 사항

- **DFS 채널 진입 비용**: 드라이버에 따라 CAC(Channel Availability Check) 시간 필요. 듀얼 어댑터의 dfs 어댑터가 미지원이면 첫 cycle (~72초) 동안 dfs 입력 없음
- **Spoofing 부분 취약**: 공격자가 매번 src MAC 바꾸면 per-source 카운터 우회. 전역 카운터가 backstop
- **Regulatory domain 의존**: 일부 채널은 국가별 제한. `iw reg get` 으로 확인
- **단일 thread observe 가정 → 해소됨**: 현재 thread-safe (mutex 적용)
- **endianness 가정**: little-endian 호스트 가정 (대부분의 x86/ARM 환경에 해당)
- **6GHz Wi-Fi 6E 미지원**: 현재 채널 분류는 2.4/5GHz만

---

## 라이선스

(프로젝트 상황에 맞게 추가)
