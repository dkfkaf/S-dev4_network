#pragma once
#include <vector>
#include "alert.h"
#include "mgmt_parser.h"

/* 모든 무선 위협 탐지 모듈의 공통 인터페이스.

   설계 원칙:
   - 입력은 파서의 ParsedFrame — 디텍터별 이벤트 구조체를 새로 정의하지 않는다.
     디텍터마다 frameType을 보고 관심 없으면 빈 vector를 반환한다.
   - 시각(ts)은 디스패처가 frame당 한 번 산정해 모든 디텍터에 전달.
     동일 frame을 본 모든 디텍터의 시간선이 일치하도록.
   - observe()는 stateful해도 됨 (sliding window, BSSID 추적 등).
   - 멀티 캡처 스레드(듀얼 어댑터)가 동시 호출 가능 — 구현체가 thread-safe 보장.
   - name()은 로그/메트릭 식별자 — 짧은 snake_case 권장 (e.g. "deauth_flood"). */
class IDetector {
public:
    virtual ~IDetector() = default;

    virtual const char* name() const = 0;

    virtual std::vector<Alert> observe(TimePoint ts, const ParsedFrame& frame) = 0;
};
