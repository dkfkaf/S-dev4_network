#pragma once
#include <cstdint>
#include <cstddef>
#include <string>
#include <optional>
#include "mac.h"

// 파싱된 802.11 management frame 정보
struct ParsedFrame {
    std::string frameType;   // "Beacon", "ProbeReq", "ProbeResp", "Deauth", "Auth", "AssocReq", "AssocResp"
    Mac         src;         // addr2 (송신자)
    Mac         dst;         // addr1 (수신자)
    Mac         bssid;       // addr3 (BSSID)
    std::string ssid;        // Tag 0 값; hasSsid=false면 의미 없음
    bool        hasSsid = false; // SSID 태그 존재 여부 (hidden SSID는 hasSsid=true, ssid="")
    int8_t      rssi    = 0; // Radiotap DBM_SIGNAL (dBm)
    bool        hasRssi = false;
};

//  data 포인터가 가리키는 len 바이트 짜리 raw 패킷을 파생해서, 성공 시 ParsedFrame 반환. 비관리 프레임이거나 파싱 실패 시 std::nullopt.
std::optional<ParsedFrame> parse_mgmt_frame(const uint8_t* data, size_t len);
