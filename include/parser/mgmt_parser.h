#pragma once
#include <cstdint>
#include <cstddef>
#include <string>
#include <optional>
#include "dot11.h"
#include "mac.h"

struct ParsedFrame {
    Dot11MgmtSubtype frameType;
    Mac              src;
    Mac              dst;
    Mac              bssid;
    std::optional<std::string> ssid;
    std::optional<int8_t>      rssi;
    std::optional<uint16_t>    reasonCode;  // Deauth 프레임에서만 채워짐
    std::optional<int>         channel;     // radiotap에서 추출 (없으면 nullopt)
};

std::optional<ParsedFrame> parse_mgmt_frame(const uint8_t* data, size_t len);
