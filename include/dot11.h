#pragma once
#include <cstdint>
#include <cstddef>
#include <cstring>
#include "mac.h"

#pragma pack(push, 1)

struct Dot11RadioTap {
    uint8_t  it_version;
    uint8_t  it_pad;
    uint16_t it_len;
    uint32_t it_present;

    static constexpr uint32_t PRESENT_TSFT        = 1u << 0;
    static constexpr uint32_t PRESENT_FLAGS       = 1u << 1;
    static constexpr uint32_t PRESENT_RATE        = 1u << 2;
    static constexpr uint32_t PRESENT_CHANNEL     = 1u << 3;
    static constexpr uint32_t PRESENT_FHSS        = 1u << 4;
    static constexpr uint32_t PRESENT_DBM_SIGNAL  = 1u << 5;
    static constexpr uint32_t PRESENT_DBM_NOISE   = 1u << 6;
    static constexpr uint32_t PRESENT_LOCK_QUAL   = 1u << 7;
    static constexpr uint32_t PRESENT_TX_ATTEN    = 1u << 8;
    static constexpr uint32_t PRESENT_DB_TX_ATTEN = 1u << 9;
    static constexpr uint32_t PRESENT_DBM_TX_PWR  = 1u << 10;
    static constexpr uint32_t PRESENT_ANTENNA     = 1u << 11;
    static constexpr uint32_t PRESENT_DB_SIGNAL   = 1u << 12;
    static constexpr uint32_t PRESENT_DB_NOISE    = 1u << 13;
    static constexpr uint32_t PRESENT_RX_FLAGS    = 1u << 14;
    static constexpr uint32_t PRESENT_MCS         = 1u << 19;
    static constexpr uint32_t PRESENT_EXT         = 1u << 31;

    static constexpr uint8_t FLAG_CFP        = 0x01;
    static constexpr uint8_t FLAG_SHORT_PRE  = 0x02;
    static constexpr uint8_t FLAG_WEP        = 0x04;
    static constexpr uint8_t FLAG_FRAG       = 0x08;
    static constexpr uint8_t FLAG_FCS_AT_END = 0x10;
    static constexpr uint8_t FLAG_DATAPAD    = 0x20;

    static size_t alignTo(size_t cursor, size_t align) {
        return (cursor + align - 1) & ~(align - 1);
    }

    bool hasFCS(const uint8_t* rtBuf) const {
        if (!(it_present & PRESENT_FLAGS)) return false;

        size_t   cursor = sizeof(Dot11RadioTap);
        uint32_t p      = it_present;

        while (p & PRESENT_EXT) {
            if (cursor + sizeof(p) > it_len) return false;
            std::memcpy(&p, rtBuf + cursor, sizeof(p));
            cursor += sizeof(p);
        }

        if (it_present & PRESENT_TSFT) {
            cursor  = alignTo(cursor, sizeof(uint64_t));
            cursor += sizeof(uint64_t);
        }

        if (cursor >= it_len) return false;
        return (rtBuf[cursor] & FLAG_FCS_AT_END) != 0;
    }

    uint16_t len() const { return it_len; }

    Dot11RadioTap(uint16_t initLen = sizeof(Dot11RadioTap), uint32_t present = 0)
        : it_version(0), it_pad(0), it_len(initLen), it_present(present) {}

    size_t hasFCS_dataEnd(const uint8_t* rtBuf, size_t capturedLen) const {
        return capturedLen - (hasFCS(rtBuf) ? 4 : 0);
    }
};

struct Dot11 {
    uint16_t frameControl;
    uint16_t duration;
    Mac      addr1;
    Mac      addr2;
    Mac      addr3;
    uint16_t seqCtrl;

    void setDst(const Mac& m) { addr1 = m; }
    void setSrc(const Mac& m) { addr2 = m; }
    void setBss(const Mac& m) { addr3 = m; }

    void advanceSeq(uint16_t& txSeq) {
        seqCtrl = static_cast<uint16_t>((txSeq++ & 0x0FFF) << 4);
    }
};

struct Beacon {
    uint64_t timestamp;
    uint16_t beaconInterval;
    uint16_t capabilityInfo;

    struct CsaTag {
        uint8_t tagNumber   = 37;
        uint8_t tagLength   = 3;
        uint8_t switchMode  = 1;
        uint8_t newChannel  = 11;
        uint8_t switchCount = 0;
    };

    struct EcsaTag {
        uint8_t tagNumber   = 60;
        uint8_t tagLength   = 4;
        uint8_t switchMode  = 1;
        uint8_t newOpClass  = 81;
        uint8_t newChannel  = 11;
        uint8_t switchCount = 0;
    };
};

// Deauthentication 고정 파라미터
struct Deauth {
    uint16_t reasonCode;
};

// Authentication 고정 파라미터
struct Auth {
    uint16_t authAlgorithm;
    uint16_t authSeqNum;
    uint16_t statusCode;
};

// Association Request 고정 파라미터
struct AssocReq {
    uint16_t capabilityInfo;
    uint16_t listenInterval;
};

// Association Response 고정 파라미터
struct AssocResp {
    uint16_t capabilityInfo;
    uint16_t statusCode;
    uint16_t associationId;
};

#pragma pack(pop)

// 802.11 frame type (frameControl 하위 바이트 bits 2-3)
inline constexpr uint8_t DOT11_TYPE_MGMT = 0x00;

// Management frame subtypes (frameControl 하위 바이트 bits 4-7)
inline constexpr uint8_t MGMT_SUBTYPE_ASSOC_REQ  = 0;
inline constexpr uint8_t MGMT_SUBTYPE_ASSOC_RESP = 1;
inline constexpr uint8_t MGMT_SUBTYPE_PROBE_REQ  = 4;
inline constexpr uint8_t MGMT_SUBTYPE_PROBE_RESP = 5;
inline constexpr uint8_t MGMT_SUBTYPE_BEACON     = 8;
inline constexpr uint8_t MGMT_SUBTYPE_AUTH       = 11;
inline constexpr uint8_t MGMT_SUBTYPE_DEAUTH     = 12;

static_assert(sizeof(Mac)              == 6,  "Mac must be 6 bytes");
static_assert(sizeof(Dot11RadioTap)    == 8,  "Dot11RadioTap fixed header must be 8 bytes");
static_assert(sizeof(Dot11)            == 24, "Dot11 must be 24 bytes");
static_assert(sizeof(Beacon)           == 12, "Beacon fixed params must be 12 bytes");
static_assert(sizeof(Beacon::CsaTag)   == 5,  "CsaTag must be 5 bytes");
static_assert(sizeof(Beacon::EcsaTag)  == 6,  "EcsaTag must be 6 bytes");
static_assert(sizeof(Deauth)           == 2,  "Deauth must be 2 bytes");
static_assert(sizeof(Auth)             == 6,  "Auth must be 6 bytes");
static_assert(sizeof(AssocReq)         == 4,  "AssocReq must be 4 bytes");
static_assert(sizeof(AssocResp)        == 6,  "AssocResp must be 6 bytes");
