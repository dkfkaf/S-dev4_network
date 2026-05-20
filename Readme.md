# wips-parser

실제로 캡처한 raw 무선 패킷에서 802.11 management frame을 파싱하는 C++17 프로젝트.

지원하는 management frame:
- Beacon
- Probe Request / Probe Response
- Authentication / Deauthentication
- Association Request / Association Response

각 프레임에서 SSID, BSSID, Source MAC, Destination MAC, RSSI(Radiotap)를 추출한다.

---

## 요구 사항

- Linux (Ubuntu / Debian / Fedora / Arch 등)
- C++17 컴파일러 (g++ 9 이상 또는 clang++ 10 이상)
- CMake 3.16 이상
- libpcap (개발 헤더 포함)
- monitor mode를 지원하는 무선 인터페이스

---

## 의존성 설치

### Ubuntu / Debian
```bash
sudo apt update
sudo apt install build-essential cmake libpcap-dev
```

### Fedora / RHEL
```bash
sudo dnf install gcc-c++ cmake libpcap-devel
```

### Arch Linux
```bash
sudo pacman -S base-devel cmake libpcap
```

---

## 빌드

프로젝트 루트에서 out-of-source 빌드를 수행한다.

```bash
mkdir -p build
cd build
cmake ..
cmake --build . -j
```

빌드가 끝나면 `build/wips-parser` 실행 파일이 생성된다.

빌드 타입을 명시하려면 다음과 같이 실행한다.
```bash
cmake -DCMAKE_BUILD_TYPE=Release ..
```

---

## 무선 인터페이스 monitor mode 설정

`wips-parser`는 radiotap 헤더(DLT_IEEE802_11_RADIO)가 붙은 패킷만 받는다.
따라서 사용 전에 인터페이스를 monitor mode로 전환해야 한다.

### 방법 1: iw 사용
```bash
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
```

### 방법 2: airmon-ng 사용 (aircrack-ng 패키지)
```bash
sudo airmon-ng check kill
sudo airmon-ng start wlan0
```
보통 `wlan0mon` 같은 monitor 인터페이스가 생성된다.

---

## 실행

`pcap_open_live`는 root 권한이 필요하다.

```bash
sudo ./wips-parser <interface>
```

예시:
```bash
sudo ./wips-parser wlan0mon
```

출력 예시:
```
[*] interface : wlan0mon
[*] 802.11 management frame 캡처 시작 ... (Ctrl+C to stop)
[Beacon]    src=AA:BB:CC:DD:EE:FF  dst=FF:FF:FF:FF:FF:FF  bssid=AA:BB:CC:DD:EE:FF  ssid="MyWiFi"  rssi=-42dBm
[ProbeReq]  src=11:22:33:44:55:66  dst=FF:FF:FF:FF:FF:FF  bssid=FF:FF:FF:FF:FF:FF  ssid=""        rssi=-70dBm
```

종료: `Ctrl+C`

---

## 디렉터리 구조

```
.
├─ CMakeLists.txt
├─ Readme.md
├─ CLAUDE.md
├─ csa/                  # 기존 CSA 구현 (참고용)
├─ include/              # 헤더 파일
│  ├─ pch.h
│  ├─ mac.h
│  ├─ dot11.h
│  └─ mgmt_parser.h
├─ src/                  # 소스 파일
│  ├─ main.cpp
│  └─ parser.cpp
└─ samples/              # 샘플 캡처 파일 (선택)
```
