#pragma once
#include <cstdint>
#include <cstddef>
#include "mac.h"

// ============================================================
// build_frame(): Deauth 또는 Auth 패킷 1개를 버퍼에 만들고 길이를 반환
// ------------------------------------------------------------
//  파라미터:
//   buf   : 만들어진 패킷을 저장할 버퍼 포인터 (uint8_t* = 1바이트 포인터)
//   da    : Destination Address (이 패킷을 받을 MAC 주소)
//   sa    : Source Address (이 패킷을 보내는 척할 MAC 주소)
//   bssid : AP의 BSSID (공유기 MAC 주소)
//   isAuth: true면 Authentication 패킷, false면 Deauthentication 패킷
//   seq   : 12비트 시퀀스 번호 (0~4095, 넘으면 자동으로 0부터 다시 시작)
//  반환값:
//   완성된 패킷의 총 바이트 수
// ============================================================
size_t build_frame(uint8_t* buf,
                   const Mac& da,
                   const Mac& sa,
                   const Mac& bssid,
                   bool isAuth,
                   uint16_t seq);
