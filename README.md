# RadioHdr

802.11 pcap 파일의 **RadioTap 헤더**를 파싱하여 각 패킷의 **안테나 수신 신호 세기(Power)** 와 **FCS 존재 여부**를 추출하는 C++ 클래스입니다.

---

## 파일 구성

```
radiohdr.h      # 클래스 선언
radiohdr.cpp    # 클래스 구현
```

---

## 빌드 방법

별도 외부 라이브러리 없이 **C++11 이상**이면 컴파일됩니다.

```bash
# 본인 프로젝트에 radiohdr.h / radiohdr.cpp 를 추가한 뒤 함께 컴파일
g++ -std=c++11 main.cpp radiohdr.cpp -o my_program
```

---

## API

### `bool loadPcap(const std::string& filename)`

pcap 파일을 불러와 모든 패킷의 RadioTap 헤더를 파싱합니다.

- 성공 시 `true`, 실패 시 `false` 반환
- 링크 타입이 `LINKTYPE_IEEE802_11_RADIOTAP (127)` 이 아닌 파일은 실패 처리됩니다
- 표준 pcap 및 나노초 타임스탬프 pcap 모두 지원합니다

```cpp
RadioHdr hdr;
if (!hdr.loadPcap("capture.pcap")) {
    // 파일 열기 실패 또는 지원하지 않는 포맷
}
```

---

### `int8_t getPower(int pkt_index) const`

`pkt_index` 번째 패킷(0-based)의 **안테나 수신 신호 세기**를 dBm 단위로 반환합니다.

| 상황 | 반환값 |
|------|--------|
| 정상 | 신호 세기 (예: `-47`, `-23`) |
| RadioTap에 Signal 필드 없음 | `INT8_MIN` (`-128`) |
| 인덱스 범위 초과 | `INT8_MIN` (`-128`) |

```cpp
int8_t power = hdr.getPower(0);   // 첫 번째 패킷의 power
if (power != INT8_MIN) {
    printf("Power: %d dBm\n", (int)power);
}
```

---

### `bool hasFCS(int pkt_index) const`

`pkt_index` 번째 패킷(0-based)에 **FCS(Frame Check Sequence)** 가 붙어 있으면 `true`를 반환합니다.

| 상황 | 반환값 |
|------|--------|
| FCS 있음 | `true` |
| FCS 없음 | `false` |
| RadioTap에 Flags 필드 없음 | `false` |
| 인덱스 범위 초과 | `false` |

```cpp
bool fcs = hdr.hasFCS(0);   // 첫 번째 패킷의 FCS 여부
printf("FCS: %s\n", fcs ? "YES" : "NO");
```

---

### `int getPacketCount() const`

로드된 전체 패킷 수를 반환합니다.

```cpp
printf("총 패킷 수: %d\n", hdr.getPacketCount());
```

---

## 사용 예제

```cpp
#include "radiohdr.h"
#include <cstdio>

int main() {
    RadioHdr hdr;

    if (!hdr.loadPcap("beacon-galaxy7-testap.pcap")) {
        printf("파일 로드 실패\n");
        return 1;
    }

    int total = hdr.getPacketCount();
    printf("패킷 수: %d\n", total);

    for (int i = 0; i < total; i++) {
        int8_t power = hdr.getPower(i);
        bool   fcs   = hdr.hasFCS(i);

        printf("pkt#%d  power=%d dBm  FCS=%s\n",
               i, (int)power, fcs ? "YES" : "NO");
    }

    return 0;
}
```

**실행 결과 예시** (`beacon-galaxy7-testap.pcap`):

```
패킷 수: 1
pkt#0  power=-24 dBm  FCS=YES
```

---

## 검증된 pcap 파일 목록

아래 파일들로 정확도를 확인했습니다.

| 파일 | Power (dBm) | FCS |
|------|:-----------:|:---:|
| beacon-a2000ua-testap.pcap | -76 | YES |
| beacon-a2000ua-testap5g.pcap | -9 | YES |
| beacon-awus051nh-testap.pcap | -5 | NO |
| beacon-awus051nh-testap5g.pcap | -17 | NO |
| beacon-daiso-mywifi.pcap | -47 | YES |
| beacon-forcerecon-testap.pcap | -28 | YES |
| beacon-forcerecon-testap5g.pcap | -28 | YES |
| beacon-galaxy7-testap.pcap | -24 | YES |
| beacon-galaxy7-testap5g.pcap | -29 | YES |
| beacon-nexus5-testap.pcap | -38 | YES |
| beacon-nexus5-testap5g.pcap | -27 | YES |
| dot11-sample.pcap | -23 | NO |

---

## 동작 원리 (간략)

각 패킷 앞에는 **RadioTap 헤더**가 붙어 있으며, 헤더 안의 `it_present` 비트맵이 어떤 필드가 존재하는지를 알려줍니다.

- **Power** → `it_present`의 **bit 5** (dBm Antenna Signal) 필드, `int8_t` (signed)
- **FCS** → `it_present`의 **bit 1** (Flags) 필드의 **bit 4 (0x10)**

각 필드는 순서와 정렬(alignment) 규칙이 정해져 있으므로, 앞 필드부터 순서대로 오프셋을 계산하며 파싱합니다.
