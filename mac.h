#pragma once
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <stdexcept>

// Mac 구조체 
/*객체가 만들어질때 자동으로 생성되는 생성자(함수)암*/
struct Mac {
    uint8_t mac_[6]; // MAC 주소를 담는 1바이트(uint8_t) 배열 6개 = 총 6바이트

    // ------------------------------------------------
    // 생성자(constructor): Mac 객체를 만들 때 자동으로 호출되는 함수
    // ------------------------------------------------

    // Mac m; 처럼 아무 값 없이 만들면 모든 바이트를 0으로 초기화
    // std::memset(채울_주소, 채울_값, 채울_바이트_수);
    Mac() { std::memset(mac_, 0, 6); }

    // 문자열("AA:BB:CC:DD:EE:FF")을 받아서 Mac 객체를 만드는 생성자
    Mac(const std::string& s) {  // s : 복사 없이 원본 문자열을 받음, 수정 안 함
        *this = fromString(s);   // fromString()으로 문자열을 Mac으로 변환한 뒤,
                                 // *this(내 자신)에 대입
    }


    // ------------------------------------------------
    // 변환 함수
    // ------------------------------------------------

    // toString(): MAC 주소를 "AA:BB:CC:DD:EE:FF" 형식의 문자열로 변환
    std::string toString() const {
        char buf[18]; // "XX:XX:XX:XX:XX:XX\0" = 17글자 + null종료 = 18바이트
        // %02X : 16진수로 출력, 2자리 미만이면 앞에 0 채움 (예: 5 -> "05")
        std::snprintf(buf, sizeof(buf),
                      "%02X:%02X:%02X:%02X:%02X:%02X",
                      mac_[0], mac_[1], mac_[2],
                      mac_[3], mac_[4], mac_[5]);
        return std::string(buf); // char 배열을 std::string으로 변환하여 반환
    }


    // ------------------------------------------------
    // 정적 팩토리 함수 (static): 객체 없이 Mac::함수명() 으로 호출 가능
    // ------------------------------------------------

    // fromString(): "AA:BB:CC:DD:EE:FF" 형식 문자열을 Mac 객체로 변환
    static Mac fromString(const std::string& s) {
        unsigned int v[6] = {0}; // 파싱된 6개의 숫자를 임시 저장 (int 크기로 받아서 범위 검증)
        char extra = 0;          // 파싱 후 남는 문자가 있는지 확인용
        // sscanf: 문자열에서 형식에 맞게 값을 읽음
        // "%x:%x:..." : 16진수 숫자 6개를 콜론 구분으로 읽음
        // 마지막 %c : 뒤에 남는 문자가 있으면 extra에 저장 (검증용)
        int n = std::sscanf(s.c_str(), "%x:%x:%x:%x:%x:%x%c",
                            &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &extra);
        // n == 6 이면 정상 파싱, 7이거나 6 미만이면 형식 오류
        if (n != 6) {
            throw std::invalid_argument("invalid MAC: " + s); // 예외 발생 (오류 신호)
        }

        Mac m; // 결과를 담을 빈 Mac 객체 생성
        for (int i = 0; i < 6; ++i) {
            // 각 바이트가 0~255(0xFF) 범위 안인지 확인
            if (v[i] > 0xFF) {
                throw std::invalid_argument("invalid MAC: " + s);
            }
            // static_cast<uint8_t>: int 값을 1바이트 정수로 안전하게 변환
            m.mac_[i] = static_cast<uint8_t>(v[i]);
        }
        return m; // 완성된 Mac 객체 반환
    }

    // broadcast(): 브로드캐스트 주소 FF:FF:FF:FF:FF:FF 를 만들어 반환
    static Mac broadcast() {
        Mac m;
        std::memset(m.mac_, 0xFF, 6); // 6바이트 전부 0xFF(255)로 채움
        return m;
    }
};

