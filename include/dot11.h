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

    // 정의는 pack(pop) 이후 — skipExtPresents/advanceToField 자유 함수 참조
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

    // Frame Control 하위 바이트 비트 레이아웃: [subtype(4-7)][type(2-3)][version(0-1)]
    // shift+mask 로 명시적으로 추출 — 비트 필드를 쓰면 컴파일러별 레이아웃 차이로
    // 와이어 포맷이 깨질 수 있어 의도적으로 피한다.
    uint8_t type()    const { return (frameControl >> 2) & 0x3; }
    uint8_t subtype() const { return (frameControl >> 4) & 0xF; }

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

// Radiotap 필드 레이아웃 — pack 영역 밖에 정의해 size_t 자연 정렬 보장.
// 새 필드를 지원할 때는 여기 한 줄만 추가하면 advanceToField 가 자동으로 처리한다.
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

// 확장 present 워드(bit 31=EXT)를 모두 건너뛰고 첫 필드 데이터 시작 위치를 cursor 에 채움.
// 모든 radiotap 필드 추출의 공통 진입 단계.
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

// present 마스크를 따라 RADIOTAP_LAYOUT 을 순회하며 targetBit 직전까지 cursor 를 전진시킨다.
// targetBit 자체는 건너뛰지 않는다 — 호출자가 읽을 차례.
// 호출 전에 skipExtPresents 로 cursor 를 첫 필드 시작 위치로 맞춰두어야 한다.
inline bool advanceToField(uint32_t present, size_t rtLen,
                           uint32_t targetBit, size_t& cursor) {
    for (const auto& f : RADIOTAP_LAYOUT) {
        if (f.presentBit == targetBit) return true;
        if (present & f.presentBit) {
            cursor = (cursor + f.align - 1) & ~(f.align - 1);
            if (cursor + f.size > rtLen) return false;
            cursor += f.size;
        }
    }
    return false;
}

inline bool Dot11RadioTap::hasFCS(const uint8_t* rtBuf) const {
    // FLAGS 필드 자체가 없으면 FCS 비트도 확인할 수 없으므로 false.
    if (!(it_present & PRESENT_FLAGS)) return false;

    // FLAGS 필드 시작 오프셋까지 cursor 를 전진시킨다.
    //   1) 확장 present 워드들을 건너뛰고 첫 필드 데이터 위치로 이동
    //   2) 레이아웃 테이블을 따라 FLAGS 직전 필드(TSFT)까지 건너뛰기
    // 두 단계 중 하나라도 버퍼 끝을 넘으면 안전하게 false 반환.
    size_t cursor;
    if (!skipExtPresents(rtBuf, it_len, it_present, cursor)) return false;
    if (!advanceToField(it_present, it_len, PRESENT_FLAGS, cursor)) return false;

    // FLAGS 는 1바이트이므로 cursor 위치에 최소 1바이트가 남아있어야 한다.
    if (cursor >= it_len) return false;
    return (rtBuf[cursor] & FLAG_FCS_AT_END) != 0;
}
