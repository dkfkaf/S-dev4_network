#pragma once
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <vector>
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

    static constexpr uint8_t TAG_HEADER_LEN = 2;  // tagNumber(1) + tagLength(1)

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

// structPtr이 가리키는 structSize바이트를 out 끝에 추가한다.
static void append_to(std::vector<uint8_t>& out, const void* structPtr, size_t structSize) {
    const uint8_t* p = static_cast<const uint8_t*>(structPtr);
    out.insert(out.end(), p, p + structSize);
}

// 기존 Tagged Parameters에서 CSA/ECSA를 제거하고,
// 태그 번호 오름차순을 유지하며 새 csa/ecsa를 올바른 위치에 삽입한다.
inline void insert_tags_sorted(
    std::vector<uint8_t>&  out,
    const uint8_t*         tags,
    size_t                 tagsLen,
    const Beacon::CsaTag&  csa,
    const Beacon::EcsaTag& ecsa)
{
    bool csaInserted  = false;
    bool ecsaInserted = false;

    const uint8_t* tagsEnd = tags + tagsLen;

    for (const uint8_t* p = tags; tagsEnd - p >= Beacon::TAG_HEADER_LEN; ) {
        uint8_t          num    = p[0];
        uint8_t          len    = p[1];
        const uint8_t*   tagEnd = p + Beacon::TAG_HEADER_LEN + len;  // 이 태그의 끝 주소

        if (tagEnd > tagsEnd) break;  // 손상된 TLV 방어

        if (num == 37 || num == 60) { p = tagEnd; continue; }  // 기존 CSA/ECSA 제거

        // 현재 태그보다 번호가 작은 CSA/ECSA를 먼저 삽입해 정렬 유지
        if (!csaInserted  && num >= 37) { append_to(out, &csa,  sizeof(csa));  csaInserted  = true; }
        if (!ecsaInserted && num >= 60) { append_to(out, &ecsa, sizeof(ecsa)); ecsaInserted = true; }

        out.insert(out.end(), p, tagEnd);  // 기존 태그 복사
        p = tagEnd;
    }

    // 삽입 위치를 못 찾은 태그는 맨 뒤에 추가
    if (!csaInserted)  append_to(out, &csa,  sizeof(csa));
    if (!ecsaInserted) append_to(out, &ecsa, sizeof(ecsa));
}
