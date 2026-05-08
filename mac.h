// =============================================================================
// mac.h
// -----------------------------------------------------------------------------
// "MAC 주소(랜카드 주소)" 를 코드에서 다루기 위한 작은 자료형 정의 파일.
//
// MAC 주소란?
//   - 모든 네트워크 카드에 공장 출하 시 부여되는 6바이트(48비트) 짜리 고유 번호.
//   - 사람 눈에는 보통 "AA:BB:CC:DD:EE:FF" 처럼 1바이트씩 16진수로 끊어 표시.
//   - 6개의 1바이트 값이 모인 것이므로 uint8_t[6] 으로 메모리에 표현한다.
// =============================================================================
#pragma once
#include <cstdint>     // uint8_t
#include <cstdio>      // snprintf, sscanf
#include <cstring>     // memset
#include <string>      // std::string
#include <stdexcept>   // std::invalid_argument

struct Mac {
    uint8_t mac_[6];

    // -------------------------------------------------------------------------
    // 기본 생성자 : 모든 바이트를 0으로 초기화 (00:00:00:00:00:00)
    // -------------------------------------------------------------------------
    Mac() { std::memset(mac_, 0, 6); }


    explicit Mac(const std::string& s) {
        unsigned int v[6];   // sscanf 의 %x 는 unsigned int 를 요구
        char extra;          // 끝에 군더더기가 있는지 검사용
        // "%x:%x:%x:%x:%x:%x%c" 로 7개 시도해서 정확히 6개만 읽혀야 정상.
        // 7번째 %c 가 읽히면 "AA:..:FFXX" 처럼 뒤에 잡소리가 붙은 것.
        int n = std::sscanf(s.data(), "%x:%x:%x:%x:%x:%x%c",
                            &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &extra);
        if (n != 6) {
            throw std::invalid_argument("invalid MAC: " + s);
        }
        for (int i = 0; i < 6; ++i) {
            if (v[i] > 0xFF) {
                // 한 칸은 1바이트(0~0xFF) 범위여야 함
                throw std::invalid_argument("invalid MAC: " + s);
            }
            mac_[i] = static_cast<uint8_t>(v[i]);
        }
    }

    // -------------------------------------------------------------------------
    // toString() : Mac -> "AA:BB:CC:DD:EE:FF" 문자열로 변환
    // -------------------------------------------------------------------------
    std::string toString() const {
        char buf[18];   // 17글자 + 끝 '\0' = 18바이트 필요
        std::snprintf(buf, sizeof(buf),
                      "%02X:%02X:%02X:%02X:%02X:%02X",
                      mac_[0], mac_[1], mac_[2],
                      mac_[3], mac_[4], mac_[5]);
        return buf;
    }
};
