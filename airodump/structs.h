#pragma once

#include "pch.h"

#pragma pack(push, 1)

struct RadiotapHeader {
    uint8_t  version;
    uint8_t  pad;
    uint16_t len;
    uint32_t present;
};

struct Dot11Header {
    uint16_t frame_ctrl;
    uint16_t duration;
    uint8_t  addr1[6];
    uint8_t  addr2[6];
    uint8_t  addr3[6];
    uint16_t seq_ctrl;
};

struct BeaconFixed {
    uint64_t timestamp;
    uint16_t beacon_interval;
    uint16_t capability;
};

#pragma pack(pop)

struct APInfo {
    std::string bssid;
    std::string essid;
    int    beacons = 0;
    int8_t pwr     = 0;
};

struct StaInfo {
    std::string station;
    std::string bssid;
    int packets = 0;
};
