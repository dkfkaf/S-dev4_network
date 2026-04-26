#pragma once

#include "pch.h"

/*┌──────────────────────────────────────────────────────────┐
│ ① Radiotap Header (고정 8 byte)                          │ ← 무선카드가 붙임
├──────────────────────────────────────────────────────────┤
│ ② Radiotap 가변 필드 (it_present에 따라 길이 다름)         │ ← 신호세기 등
├──────────────────────────────────────────────────────────┤  ← 여기부터 진짜 802.11
│ ③ 802.11 MAC Header (24 byte)                            │ ← Dot11Header
├──────────────────────────────────────────────────────────┤
│ ④ Beacon Fixed Parameters (12 byte)                      │ ← BeaconFixed
├──────────────────────────────────────────────────────────┤
│ ⑤ Tagged Parameters (가변, SSID/채널/암호화 등)           │ ← 핵심 정보! 근데 난 안쓸거임. 어려워용...
├──────────────────────────────────────────────────────────┤
│ ⑥ FCS (4 byte, 체크섬) - 보통 잘려서 안 보임              │
└──────────────────────────────────────────────────────────┘*/


// ===== Radiotap 헤더 구조체 =====
// Wi-Fi 패킷을 전송할 때 맨 앞에 붙는 메타정보 헤더
// 실제 무선 신호 설정값들 (전송 속도, 채널 등)을 담음

#pragma pack(push, 1)

struct RadiotapHeader {
    uint8_t  version;
    uint8_t  pad;
    uint16_t len;
    uint32_t present;
};

struct Dot11Header {   /* 802.11 프레임 헤더*/
    uint16_t frame_ctrl;
    uint16_t duration;
    uint8_t  addr1[6];    //수신자 mac
    uint8_t  addr2[6];    //송신자 mac
    uint8_t  addr3[6];   // BSSID
    uint16_t seq_ctrl;
};

struct BeaconFixed {   /*AP가 자기 존재를 알리려고 주기적으로 뿌리는 신호*/
    uint64_t timestamp;
    uint16_t beacon_interval;
    uint16_t capability;
};

//원래 이 뒤에는 tag parameter 구조체가 필요하다. 근데 거기도 한번 보긴했는데 도저히 이해가 안되더라...

#pragma pack(pop)

// AP 정보 (출력용)
struct APInfo {
    std::string bssid; // AP의 MAC 주소
    std::string essid; // AP의 이름
    int beacons = 0;  // 비콘 프레임 수신 횟수
};