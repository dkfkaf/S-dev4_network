// =============================================================================
// frame.h
// -----------------------------------------------------------------------------
// 캡처한 정상 비콘(Beacon) 프레임을 가공해, CSA 태그가 들어 있는
// 공격용 비콘으로 다시 만들어 주는 함수의 "선언" 만 모아둔 헤더.
//
// 실제 동작 코드는 frame.cpp 에 있다. 헤더에는 "이 함수가 있다" 는 선언만 둔다.
// =============================================================================
#pragma once
#include <cstdint>     // uint8_t
#include <cstddef>     // size_t
#include "mac.h"       // Mac

// -----------------------------------------------------------------------------
// build_csa_beacon
//   캡처한 비콘에 CSA 태그를 끼워 넣어 송신 가능한 공격 프레임을 만든다.
//
//   outBuf       : 결과(공격용 프레임) 가 저장될 버퍼. 호출하는 쪽에서 미리 준비.
//   outBufSize   : outBuf 의 크기(바이트). 안전한 범위 안에서만 쓰도록 검사용.
//   captured     : 모니터 모드에서 캡처한 원본 비콘 (RadioTap 헤더부터 시작)
//   capturedLen  : captured 의 길이
//   useUnicast   : true  -> DA(addr1) 를 staMac 으로 교체하여 특정 단말 표적
//                  false -> DA 를 그대로 두어 broadcast(모든 단말 영향)
//   staMac       : useUnicast = true 일 때 표적 단말의 MAC
//
//   반환값       : 만들어진 공격용 프레임의 실제 길이(바이트). 실패 시 0.
// -----------------------------------------------------------------------------
size_t build_csa_beacon(uint8_t* outBuf, size_t outBufSize,
                        const uint8_t* captured, size_t capturedLen,
                        bool useUnicast, const Mac& staMac);
