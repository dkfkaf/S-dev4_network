#pragma once
#include <cstdint>
#include <cstddef>
#include "mac.h"

size_t build_csa_beacon(
    uint8_t*       outBuf,       // [출력] 결과(공격용 프레임) 가 담길 버퍼. 호출자가 미리 할당.
    size_t         outBufSize,   // [입력] outBuf 의 크기(바이트). 끼워 넣다가 넘으면 0 반환.
    const uint8_t* captured,     // [입력] 캡처한 원본 비콘 (RadioTap 헤더부터 시작)
    size_t         capturedLen,  // [입력] captured 의 전체 길이(바이트)
    bool           useUnicast,   // [입력] true=DA 를 staMac 으로 교체(특정 단말 표적), false=broadcast 유지
    const Mac&     staMac        // [입력] useUnicast=true 일 때 표적 단말의 MAC. false 면 무시.
);
