#pragma once
#include <vector>
#include "alert.h"
#include "mgmt_parser.h"

/* 모든 무선 위협 탐지 모듈의 공통 인터페이스.

   설계 원칙:
   - 입력은 파서의 ParsedFrame — 디텍터별 이벤트 구조체를 새로 정의하지 않는다.
     디텍터마다 frameType을 보고 관심 없으면 빈 vector를 반환한다.
   - timestamp는 디스패처가 frame당 한 번 산정해 모든 디텍터에 전달.
     동일 frame을 본 모든 디텍터의 시간선이 일치하도록.
   - observe()는 stateful해도 됨 (sliding window, BSSID 추적 등).
   - 멀티 캡처 스레드(듀얼 어댑터)가 동시 호출 가능 — 구현체가 thread-safe 보장.
   - virtual을 쓴 것은 이후 디텍터(Evil Twin 등) 추가 시 같은 dispatcher가 호출하기 위함. */
class IDetector {
public:
    virtual ~IDetector() = default;

    virtual std::vector<Alert> observe(TimePoint timestamp, const ParsedFrame& frame) = 0;
};
