#pragma once
#include <cstdint>
#include <cstddef>
#include "mac.h"

#pragma pack(push, 1)

struct dot11RadioTap {
    uint8_t  it_version;
    uint8_t  it_pad;
    uint16_t it_len;
    uint32_t it_present;
};

struct dot11MacHdr {
    uint16_t frameControl;
    uint16_t duration;
    Mac      addr1;
    Mac      addr2;
    Mac      addr3;
    uint16_t seqCtrl;
};

struct CsaTag {
    uint8_t tagNumber;
    uint8_t tagLength;
    uint8_t switchMode;
    uint8_t newChannel;
    uint8_t switchCount;
};

#pragma pack(pop)

/*이건 바뀔 수 있는 값이 아닌가*/
static_assert(sizeof(Mac)           == 6,  "Mac must be 6 bytes");
static_assert(sizeof(dot11RadioTap) == 8,  "dot11RadioTap must be 8 bytes");
static_assert(sizeof(dot11MacHdr)   == 24, "dot11MacHdr must be 24 bytes");
static_assert(sizeof(CsaTag)        == 5,  "CsaTag must be 5 bytes");

static constexpr size_t   BEACON_FIXED_PARAM_LEN = 12;
static constexpr uint8_t  CSA_TAG_NUMBER         = 37;
static constexpr uint8_t  CSA_TAG_LENGTH         = 3;
static constexpr uint8_t  CSA_SWITCH_MODE        = 1;
static constexpr uint8_t  CSA_NEW_CHANNEL        = 11;
static constexpr uint8_t  CSA_COUNT              = 3;
static constexpr uint32_t RT_PRESENT_TSFT        = 1u << 0;
static constexpr uint32_t RT_PRESENT_FLAGS       = 1u << 1;
static constexpr uint32_t RT_PRESENT_EXT         = 1u << 31;
static constexpr uint8_t  RT_FLAG_FCS_AT_END     = 0x10;
