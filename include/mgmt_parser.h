#pragma once
#include <cstdint>
#include <cstddef>
#include <string>
#include <optional>
#include "mac.h"

struct ParsedFrame {
    std::string frameType;
    Mac         src;
    Mac         dst;
    Mac         bssid;
    std::optional<std::string> ssid;
    std::optional<int8_t>      rssi;
};

std::optional<ParsedFrame> parse_mgmt_frame(const uint8_t* data, size_t len);
