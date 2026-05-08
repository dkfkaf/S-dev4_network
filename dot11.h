// =============================================================================
// dot11.h
// -----------------------------------------------------------------------------
// 무선랜(802.11/WiFi) 프레임이 메모리에서 어떻게 생겼는지 그대로 표현한
// "구조체(struct)" 들을 모아둔 헤더 파일.
//
// 무선 패킷의 큰 그림 (이 프로그램에서 다루는 비콘 형태):
//
//   [ RadioTap header ] [ 802.11 MAC hdr ] [ Frame body (Beacon) ]
//   - RadioTap header  : 드라이버가 붙이는 메타정보 (8B 고정 + 가변)
//   - 802.11 MAC hdr   : 송/수신 주소, 시퀀스 번호 등 (24바이트)
//   - Frame body       : 고정 파라미터 12B + 가변 길이 태그들
//
// 메모리 배치를 1바이트도 어긋나지 않게 맞추려고 #pragma pack(push, 1) 을 사용한다.
// =============================================================================
#pragma once
#include <cstdint>
#include <cstddef>
#include "mac.h"

#pragma pack(push, 1)  // 정렬을 1바이트로 (패딩 금지)

// -----------------------------------------------------------------------------
// RadioTap 헤더의 "고정 8바이트" 부분.
// 실제 wire-format 은 가변이며 it_len 필드에 실제 전체 길이가 들어 있다.
// 이 구조체는 그 고정 머리 부분만 메모리 위에 덧씌우기 위한 것.
// -----------------------------------------------------------------------------
struct dot11RadioTap {
    uint8_t  it_version;
    uint8_t  it_pad;
    uint16_t it_len;
    uint32_t it_present;
};

// -----------------------------------------------------------------------------
// 802.11 MAC 헤더 (24 바이트)
// -----------------------------------------------------------------------------
struct dot11MacHdr {
    uint16_t frameControl;
    uint16_t duration;
    Mac      addr1;        // DA (받는 사람)
    Mac      addr2;        // SA (보내는 사람)
    Mac      addr3;        // BSSID
    uint16_t seqCtrl;
};

// -----------------------------------------------------------------------------
// CSA (Channel Switch Announcement) - 5 바이트
// -----------------------------------------------------------------------------
struct CsaTag {
    uint8_t tagNumber;     // 37
    uint8_t tagLength;     // 3
    uint8_t switchMode;
    uint8_t newChannel;
    uint8_t switchCount;
};

// -----------------------------------------------------------------------------
// ECSA (Extended Channel Switch Announcement) - 6 바이트
// CSA 와 같은 목적이지만 Element ID 가 60 으로 다르고 Operating Class 필드가
// 추가되어 있다. 호환성을 위해 두 태그 모두 비콘에 끼워 넣는다.
// -----------------------------------------------------------------------------
struct EcsaTag {
    uint8_t tagNumber;     // 60
    uint8_t tagLength;     // 4
    uint8_t switchMode;
    uint8_t newOpClass;
    uint8_t newChannel;
    uint8_t switchCount;
};

#pragma pack(pop)

// 구조체 크기가 IEEE 802.11 wire-format 과 정확히 일치해야만
// 패킷 메모리 위에 그대로 덧씌울 수 있다. 컴파일러가 패딩을 끼워 넣어
// 더 커지는 사고를 빌드 단계에서 막는다.
static_assert(sizeof(Mac)           == 6,  "Mac must be 6 bytes");
static_assert(sizeof(dot11RadioTap) == 8,  "dot11RadioTap fixed header must be 8 bytes");
static_assert(sizeof(dot11MacHdr)   == 24, "dot11MacHdr must be 24 bytes");
static_assert(sizeof(CsaTag)        == 5,  "CsaTag must be 5 bytes");
static_assert(sizeof(EcsaTag)       == 6,  "EcsaTag must be 6 bytes");

// -----------------------------------------------------------------------------
// 자주 쓰이는 상수
// -----------------------------------------------------------------------------

// Beacon 고정 파라미터 (타임스탬프8 + Beacon Interval2 + Capability2 = 12B)
static constexpr size_t   BEACON_FIXED_PARAM_LEN = 12;

// CSA / ECSA 가 공유하는 채널 전환 동작 값
//   같은 채널·같은 모드·같은 카운트를 두 태그에 동시에 박는다.
static constexpr uint8_t  CHSW_NEW_CHANNEL  = 11;  // 유도할 채널 번호
static constexpr uint8_t  CHSW_SWITCH_MODE  = 1;   // 1 = 즉시 송신 정지하고 따라오라
static constexpr uint8_t  CHSW_SWITCH_COUNT = 0;   // 0 = 즉시 전환 (카운트다운 없음)

// CSA element 식별자 (5B)
static constexpr uint8_t  CSA_TAG_NUMBER    = 37;
static constexpr uint8_t  CSA_TAG_LENGTH    = 3;

// ECSA element 식별자 (6B)
static constexpr uint8_t  ECSA_TAG_NUMBER   = 60;
static constexpr uint8_t  ECSA_TAG_LENGTH   = 4;
static constexpr uint8_t  ECSA_NEW_OP_CLASS = 81;  // 2.4GHz 채널 1~13 글로벌 op class

// RadioTap it_present 비트 마스크
static constexpr uint32_t RT_PRESENT_TSFT    = 1u << 0;
static constexpr uint32_t RT_PRESENT_FLAGS   = 1u << 1;
static constexpr uint32_t RT_PRESENT_EXT     = 1u << 31;
static constexpr uint8_t  RT_FLAG_FCS_AT_END = 0x10;
