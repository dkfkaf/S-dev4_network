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
        // ── it_present 비트 (어떤 필드가 뒤에 붙어있는지)
    static constexpr uint32_t PRESENT_TSFT        = 1u << 0;  // 타임스탬프 (8바이트)
    static constexpr uint32_t PRESENT_FLAGS       = 1u << 1;  // 프레임 플래그 (1바이트)
    static constexpr uint32_t PRESENT_RATE        = 1u << 2;  // 전송 속도 (1바이트)
    static constexpr uint32_t PRESENT_CHANNEL     = 1u << 3;  // 채널 주파수+플래그 (4바이트)
    static constexpr uint32_t PRESENT_FHSS        = 1u << 4;  // 주파수 호핑 (2바이트)
    static constexpr uint32_t PRESENT_DBM_SIGNAL  = 1u << 5;  // 신호 세기 dBm (1바이트)
    static constexpr uint32_t PRESENT_DBM_NOISE   = 1u << 6;  // 노이즈 세기 dBm (1바이트)
    static constexpr uint32_t PRESENT_LOCK_QUAL   = 1u << 7;  // 신호 품질 (2바이트)
    static constexpr uint32_t PRESENT_TX_ATTEN    = 1u << 8;  // 송신 감쇠 (2바이트)
    static constexpr uint32_t PRESENT_DB_TX_ATTEN = 1u << 9;  // 송신 감쇠 dB (2바이트)
    static constexpr uint32_t PRESENT_DBM_TX_PWR  = 1u << 10; // 송신 출력 dBm (1바이트)
    static constexpr uint32_t PRESENT_ANTENNA     = 1u << 11; // 안테나 인덱스 (1바이트)
    static constexpr uint32_t PRESENT_DB_SIGNAL   = 1u << 12; // 신호 세기 dB (1바이트)
    static constexpr uint32_t PRESENT_DB_NOISE    = 1u << 13; // 노이즈 세기 dB (1바이트)
    static constexpr uint32_t PRESENT_RX_FLAGS    = 1u << 14; // 수신 플래그 (2바이트)
    static constexpr uint32_t PRESENT_MCS         = 1u << 19; // MCS 인덱스 (3바이트)
    static constexpr uint32_t PRESENT_EXT         = 1u << 31; // 비트맵 확장

    // ── FLAGS 필드 (PRESENT_FLAGS 있을 때 뒤에 붙는 1바이트)
    static constexpr uint8_t FLAG_CFP        = 0x01; // CFP 중 전송
    static constexpr uint8_t FLAG_SHORT_PRE  = 0x02; // 짧은 프리앰블
    static constexpr uint8_t FLAG_WEP        = 0x04; // WEP 암호화
    static constexpr uint8_t FLAG_FRAG       = 0x08; // 단편화됨
    static constexpr uint8_t FLAG_FCS_AT_END = 0x10; // FCS 포함 여부
    static constexpr uint8_t FLAG_DATAPAD    = 0x20; // 32비트 경계 패딩

    // 정렬 함수
    static size_t alignTo(size_t cursor, size_t align) {
        return (cursor + align - 1) & ~(align - 1);
    }

    bool hasFCS() const {
        if (!(it_present & PRESENT_FLAGS)) return false;

        const uint8_t* rt     = reinterpret_cast<const uint8_t*>(this);
        size_t   Radiotap_end = sizeof(Dot11RadioTap);
        uint32_t p = it_present;

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

    bool hasSignal() const { return (it_present & PRESENT_DBM_SIGNAL) != 0; }
    uint16_t len()   const { return it_len; }

    // 생성자: 기본값으로 최소 Radiotap 헤더 초기화 (드라이버가 나머지를 채움)
    Dot11RadioTap(uint16_t initLen = sizeof(Dot11RadioTap), uint32_t present = 0)
        : it_version(0), it_pad(0), it_len(initLen), it_present(present) {}

    // FCS가 있으면 끝 4바이트를 제외한 실제 데이터 끝 위치 반환
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

    void setDst(const Mac& m) { addr1 = m; }  // 목적지 교체
    void setSrc(const Mac& m) { addr2 = m; }  // 송신자 교체
    void setBss(const Mac& m) { addr3 = m; }  // BSS(AP) 교체

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

static_assert(sizeof(Mac)              == 6,  "Mac must be 6 bytes");
static_assert(sizeof(Dot11RadioTap)    == 8,  "Dot11RadioTap fixed header must be 8 bytes");
static_assert(sizeof(Dot11)            == 24, "Dot11 must be 24 bytes");
static_assert(sizeof(Beacon)           == 12, "Beacon fixed params must be 12 bytes");
static_assert(sizeof(Beacon::CsaTag)   == 5,  "CsaTag must be 5 bytes");
static_assert(sizeof(Beacon::EcsaTag)  == 6,  "EcsaTag must be 6 bytes");