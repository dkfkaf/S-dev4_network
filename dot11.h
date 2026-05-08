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

struct EcsaTag {
    uint8_t tagNumber;
    uint8_t tagLength;
    uint8_t switchMode;
    uint8_t newOpClass;
    uint8_t newChannel;
    uint8_t switchCount;
};

#pragma pack(pop)

static_assert(sizeof(Mac)           == 6,  "Mac must be 6 bytes");
static_assert(sizeof(dot11RadioTap) == 8,  "dot11RadioTap fixed header must be 8 bytes");
static_assert(sizeof(dot11MacHdr)   == 24, "dot11MacHdr must be 24 bytes");
static_assert(sizeof(CsaTag)        == 5,  "CsaTag must be 5 bytes");
static_assert(sizeof(EcsaTag)       == 6,  "EcsaTag must be 6 bytes");

static constexpr size_t   BEACON_FIXED_PARAM_LEN = 12;

static constexpr uint8_t  CHSW_NEW_CHANNEL  = 11;
static constexpr uint8_t  CHSW_SWITCH_MODE  = 1;
static constexpr uint8_t  CHSW_SWITCH_COUNT = 0;

static constexpr uint8_t  CSA_TAG_NUMBER    = 37;
static constexpr uint8_t  CSA_TAG_LENGTH    = 3;

static constexpr uint8_t  ECSA_TAG_NUMBER   = 60;
static constexpr uint8_t  ECSA_TAG_LENGTH   = 4;
static constexpr uint8_t  ECSA_NEW_OP_CLASS = 81;

static constexpr uint32_t RT_PRESENT_TSFT    = 1u << 0;
static constexpr uint32_t RT_PRESENT_FLAGS   = 1u << 1;
static constexpr uint32_t RT_PRESENT_EXT     = 1u << 31;
static constexpr uint8_t  RT_FLAG_FCS_AT_END = 0x10;
