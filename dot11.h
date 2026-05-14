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

    bool hasFCS() const {
        if (!(it_present & PRESENT_FLAGS)) return false;

        const uint8_t* rt     = reinterpret_cast<const uint8_t*>(this);
        size_t   Radiotap_end = sizeof(Dot11RadioTap);
        uint32_t p            = it_present;

        while (p & PRESENT_EXT) {
            std::memcpy(&p, rt + Radiotap_end, sizeof(p));
            Radiotap_end += sizeof(p);
        }

        if (it_present & PRESENT_TSFT) {
            Radiotap_end  = alignTo(Radiotap_end, sizeof(uint64_t));
            Radiotap_end += sizeof(uint64_t);
        }

        return (rt[Radiotap_end] & FLAG_FCS_AT_END) != 0;
    }

    bool     hasSignal() const { return (it_present & PRESENT_DBM_SIGNAL) != 0; }
    uint16_t len()       const { return it_len; }

    Dot11RadioTap(uint16_t initLen = sizeof(Dot11RadioTap), uint32_t present = 0)
        : it_version(0), it_pad(0), it_len(initLen), it_present(present) {}

    size_t hasFCS_dataEnd(size_t capturedLen) const {
        return capturedLen - (hasFCS() ? 4 : 0);
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

    void seqNum(uint16_t& txSeq) {
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

#pragma pack(pop)

static_assert(sizeof(Mac)             == 6,  "Mac must be 6 bytes");
static_assert(sizeof(Dot11RadioTap)   == 8,  "Dot11RadioTap fixed header must be 8 bytes");
static_assert(sizeof(Dot11)           == 24, "Dot11 must be 24 bytes");
static_assert(sizeof(Beacon)          == 12, "Beacon fixed params must be 12 bytes");
static_assert(sizeof(Beacon::CsaTag)  == 5,  "CsaTag must be 5 bytes");
static_assert(sizeof(Beacon::EcsaTag) == 6,  "EcsaTag must be 6 bytes");
