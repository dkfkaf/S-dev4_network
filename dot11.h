#pragma once
#include <cstdint>
#include "mac.h"

#pragma pack(push, 1)

struct dot11RadioTap {
    uint8_t  it_version;
    uint8_t  it_pad;
    uint16_t it_len;
    uint32_t it_present;
};

struct dot11MacHdr {
    static constexpr uint16_t FC_DEAUTH = 0x00C0;

    uint16_t frameControl;
    uint16_t duration;
    Mac      addr1;
    Mac      addr2;
    Mac      addr3;
    uint16_t seqCtrl;
};

#pragma pack(pop)
