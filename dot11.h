#pragma once
#include <cstdint>
#include "mac.h"

// ============================================================
// 802.11 / Radiotap 헤더 구조체 정의
// ============================================================
#pragma pack(push, 1) // 1바이트 정렬: 패딩 없이 선언 순서대로 메모리에 배치

// Radiotap header 구조체 (최소 8바이트 형태)
struct dot11RadioTap {
    uint8_t  it_version; // 항상 0 (버전 번호, 현재는 0만 존재)
    uint8_t  it_pad;     // 항상 0 (정렬용 빈 바이트)
    uint16_t it_len;     // radiotap 헤더 전체 길이 (리틀엔디안, 여기서는 8)
    uint32_t it_present; // 어떤 추가 필드가 있는지 나타내는 비트 플래그 (0 = 추가 없음)
};

// 802.11 MAC header 구조체 (관리 프레임용, 24바이트)
// Deauth/Auth 패킷의 실제 헤더 정보
struct dot11MacHdr {
    // Frame Control 값: 패킷 종류를 나타내는 2바이트 필드
    //static const 모두가 공유하는 변경 불가능한 값==절대 안바뀌는 상수==객체 없이 dot11machdr::fc_deauth로 접근가능
    static const uint16_t FC_DEAUTH = 0x00C0;
    static const uint16_t FC_AUTH   = 0x00B0;

    uint16_t frameControl; // 프레임 종류 (FC_DEAUTH 또는 FC_AUTH)
    uint16_t duration;     // 전송 지속 시간 (μs 단위, 0x013A = 314μs)
    Mac      addr1;        // Destination Address (DA): 이 패킷을 받을 기기의 MAC
    Mac      addr2;        // Source Address (SA): 이 패킷을 보낸 기기의 MAC (위조)
    Mac      addr3;        // BSSID: AP(공유기)의 MAC 주소
    uint16_t seqCtrl;      // Sequence Control: 상위 12비트=시퀀스번호, 하위 4비트=단편번호
};

#pragma pack(pop) // 패딩 설정을 이전 상태로 복원

