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

    uint16_t len() const { return it_len; }

    bool hasFCS(const uint8_t* rtBuf) const;

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

    uint8_t type()    const { return (frameControl >> 2) & 0x3; }
    uint8_t subtype() const { return (frameControl >> 4) & 0xF; }

    void setDst(const Mac& m) { addr1 = m; }
    void setSrc(const Mac& m) { addr2 = m; }
    void setBss(const Mac& m) { addr3 = m; }

    void advanceSeq(uint16_t& txSeq) {
        seqCtrl = static_cast<uint16_t>((txSeq++ & 0x0FFF) << 4);
    }
};

// IEEE 802.11 Information Element 공통 헤더 뷰. CsaTag/EcsaTag도 처음 두 바이트(num, len)가 동일 레이아웃.
// 본질이 byte buffer ↔ typed pointer reinterpretation이라 캐스트는 의도적으로 C-style을 사용한다.
struct Dot11Tag {
    uint8_t num;
    uint8_t len;

    bool isValid(const uint8_t* end) const {
        const uint8_t* p = (const uint8_t*)this;
        return (p + sizeof(Dot11Tag) <= end) && (p + sizeof(Dot11Tag) + len <= end);
    }

    uint8_t*       value()       { return (uint8_t*)(this + 1); }
    const uint8_t* value() const { return (const uint8_t*)(this + 1); }

    Dot11Tag*       next()       { return (Dot11Tag*)((uint8_t*)this + sizeof(Dot11Tag) + len); }
    const Dot11Tag* next() const { return (const Dot11Tag*)((const uint8_t*)this + sizeof(Dot11Tag) + len); }
};

struct Beacon {
    uint64_t timestamp;
    uint16_t beaconInterval;
    uint16_t capabilityInfo;

    struct CsaTag {
        uint8_t num         = 37;
        uint8_t len         = 3;
        uint8_t switchMode  = 1;
        uint8_t newChannel  = 11;
        uint8_t switchCount = 0;
    };

    struct EcsaTag {
        uint8_t num         = 60;
        uint8_t len         = 4;
        uint8_t switchMode  = 1;
        uint8_t newOpClass  = 81;
        uint8_t newChannel  = 11;
        uint8_t switchCount = 0;
    };
};

struct Deauth {
    uint16_t reasonCode;
};

struct Auth {
    uint16_t authAlgorithm;
    uint16_t authSeqNum;
    uint16_t statusCode;
};

struct AssocReq {
    uint16_t capabilityInfo;
    uint16_t listenInterval;
};

struct AssocResp {
    uint16_t capabilityInfo;
    uint16_t statusCode;
    uint16_t associationId;
};

#pragma pack(pop)

// frameControl bits 3-2 — frame type
enum Dot11Type : uint8_t {
    DOT11_TYPE_MGMT = 0x00,
    DOT11_TYPE_CTRL = 0x01,
    DOT11_TYPE_DATA = 0x02,
};

// frameControl bits 7-4 — management frame subtype
enum Dot11MgmtSubtype : uint8_t {
    MGMT_SUBTYPE_ASSOC_REQ  = 0,
    MGMT_SUBTYPE_ASSOC_RESP = 1,
    MGMT_SUBTYPE_PROBE_REQ  = 4,
    MGMT_SUBTYPE_PROBE_RESP = 5,
    MGMT_SUBTYPE_BEACON     = 8,
    MGMT_SUBTYPE_AUTH       = 11,
    MGMT_SUBTYPE_DEAUTH     = 12,
};

inline const char* toString(Dot11MgmtSubtype s) {
    switch (s) {
        case MGMT_SUBTYPE_ASSOC_REQ:  return "AssocReq";
        case MGMT_SUBTYPE_ASSOC_RESP: return "AssocResp";
        case MGMT_SUBTYPE_PROBE_REQ:  return "ProbeReq";
        case MGMT_SUBTYPE_PROBE_RESP: return "ProbeResp";
        case MGMT_SUBTYPE_BEACON:     return "Beacon";
        case MGMT_SUBTYPE_AUTH:       return "Auth";
        case MGMT_SUBTYPE_DEAUTH:     return "Deauth";
    }
    return "Unknown";
}

static_assert(sizeof(Mac)              == 6,  "Mac must be 6 bytes");
static_assert(sizeof(Dot11RadioTap)    == 8,  "Dot11RadioTap fixed header must be 8 bytes");
static_assert(sizeof(Dot11)            == 24, "Dot11 must be 24 bytes");
static_assert(sizeof(Dot11Tag)         == 2,  "Dot11Tag must be 2 bytes");
static_assert(sizeof(Beacon)           == 12, "Beacon fixed params must be 12 bytes");
static_assert(sizeof(Beacon::CsaTag)   == 5,  "CsaTag must be 5 bytes");
static_assert(sizeof(Beacon::EcsaTag)  == 6,  "EcsaTag must be 6 bytes");
static_assert(sizeof(Deauth)           == 2,  "Deauth must be 2 bytes");
static_assert(sizeof(Auth)             == 6,  "Auth must be 6 bytes");
static_assert(sizeof(AssocReq)         == 4,  "AssocReq must be 4 bytes");
static_assert(sizeof(AssocResp)        == 6,  "AssocResp must be 6 bytes");

struct RadiotapFieldDesc { uint32_t presentBit; size_t size; size_t align; };
inline constexpr RadiotapFieldDesc RADIOTAP_LAYOUT[] = {
    { Dot11RadioTap::PRESENT_TSFT,        8, 8 },
    { Dot11RadioTap::PRESENT_FLAGS,       1, 1 },
    { Dot11RadioTap::PRESENT_RATE,        1, 1 },
    { Dot11RadioTap::PRESENT_CHANNEL,     4, 2 },
    { Dot11RadioTap::PRESENT_FHSS,        2, 1 },
    { Dot11RadioTap::PRESENT_DBM_SIGNAL,  1, 1 },
    { Dot11RadioTap::PRESENT_DBM_NOISE,   1, 1 },
    { Dot11RadioTap::PRESENT_LOCK_QUAL,   2, 2 },
    { Dot11RadioTap::PRESENT_TX_ATTEN,    2, 2 },
    { Dot11RadioTap::PRESENT_DB_TX_ATTEN, 2, 2 },
    { Dot11RadioTap::PRESENT_DBM_TX_PWR,  1, 1 },
    { Dot11RadioTap::PRESENT_ANTENNA,     1, 1 },
    { Dot11RadioTap::PRESENT_DB_SIGNAL,   1, 1 },
    { Dot11RadioTap::PRESENT_DB_NOISE,    1, 1 },
    { Dot11RadioTap::PRESENT_RX_FLAGS,    2, 2 },
};

inline size_t alignTo(size_t cursor, size_t align) {
    return (cursor + align - 1) & ~(align - 1);
}

inline bool skipExtPresents(const uint8_t* rtBuf, size_t rtLen,
                            uint32_t firstPresent, size_t& cursor) {
    cursor = sizeof(Dot11RadioTap);
    uint32_t p = firstPresent;
    while (p & Dot11RadioTap::PRESENT_EXT) {
        if (cursor + sizeof(uint32_t) > rtLen) return false;
        std::memcpy(&p, rtBuf + cursor, sizeof(p));
        cursor += sizeof(uint32_t);
    }
    return true;
}

inline bool advanceToField(uint32_t present, size_t rtLen,
                           uint32_t targetBit, size_t& cursor) {
    for (const auto& f : RADIOTAP_LAYOUT) {
        if (f.presentBit == targetBit) return true;
        if (present & f.presentBit) {
            cursor = alignTo(cursor, f.align);
            if (cursor + f.size > rtLen) return false;
            cursor += f.size;
        }
    }
    return false;
}

inline bool Dot11RadioTap::hasFCS(const uint8_t* rtBuf) const {
    if (!(it_present & PRESENT_FLAGS)) return false;

    size_t cursor;
    if (!skipExtPresents(rtBuf, it_len, it_present, cursor)) return false;
    if (!advanceToField(it_present, it_len, PRESENT_FLAGS, cursor)) return false;

    if (cursor >= it_len) return false;
    return (rtBuf[cursor] & FLAG_FCS_AT_END) != 0;
}
