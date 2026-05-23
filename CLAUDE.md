# CLAUDE.md

## Project Overview
이 프로젝트는 이미 구현되어 있는 **802.11 프레임 파서 코드**를 기반으로  
다음 기능을 기존 코드 스타일과 구조에 맞게 확장 구현하는 C++ 프로젝트입니다.

1. **Deauth Flood 탐지 모듈**
2. **채널 호핑(Channel Hopping) 기능**

현재 코드베이스에는 이미 다음 기능이 구현되어 있다고 가정합니다.

- Beacon / Probe / Deauth / Auth / Association 파싱
- SSID / BSSID / MAC / RSSI 추출

이 작업의 목표는 새 프로젝트를 만드는 것이 아니라,  
**기존 802.11 파서 코드 구조를 먼저 읽고 이해한 뒤, 그 구조에 맞춰 기능을 추가하는 것**입니다.

---

## Mandatory First Step
작업 시작 전에 반드시 아래를 수행합니다.

1. 기존 **802.11 파서 코드 구조**를 먼저 읽고 분석합니다.
2. 현재 파서가 어떤 흐름으로 패킷을 처리하는지 확인합니다.
3. Deauthentication 프레임이 어디서 파싱되고 어떤 구조체/클래스로 결과가 전달되는지 확인합니다.
4. 현재 코드의 네이밍, 클래스/구조체 설계, 로깅 방식, 빌드 구조(CMake 포함)를 파악합니다.
5. 새로운 기능은 반드시 **기존 802.11 파서 코드 구조를 유지한 채 확장하는 방식**으로 구현합니다.
6. 기존 파서 구조를 갈아엎거나 새 아키텍처를 도입하지 않습니다.

---

## Main Goals
다음 두 가지 기능을 구현합니다.

### 1. Deauth Flood Detection
기존 802.11 파서가 Deauthentication 프레임을 파싱한 결과를 활용하여  
**Deauth Flood 탐지 모듈**을 구현합니다.

### 2. Channel Hopping
무선 패킷 수집 범위를 넓히기 위해 **채널 호핑 기능**을 구현합니다.  
센서는 일정 주기마다 채널을 변경하며 각 채널에서 패킷을 수집할 수 있어야 합니다.

---

## Core Integration Principle
모든 구현은 반드시 아래 원칙을 따릅니다.

- 새 기능은 **기존 802.11 파서 코드 구조에 추가**합니다.
- 기존 파서가 이미 제공하는 데이터 흐름, 결과 구조체, 유틸리티, 로깅 방식을 최대한 재사용합니다.
- 기존 코드와 중복되는 별도 파서를 새로 만들지 않습니다.
- 기능 추가를 위해 구조 변경이 필요하더라도 최소 범위로 제한합니다.
- 기존 파서 코드의 스타일, 책임 분리 방식, 네이밍을 우선적으로 따릅니다.

---

## Deauth Flood Detection Requirements

### Sliding Window Counter
슬라이딩 윈도우 카운터는 **타임스탬프 큐(timestamp queue)** 방식으로 구현합니다.

구현 원칙:
- Deauth 프레임이 들어올 때마다 현재 timestamp를 저장합니다.
- 윈도우 범위를 벗어난 오래된 timestamp는 제거합니다.
- 큐의 현재 길이를 최근 윈도우 내 이벤트 수로 사용합니다.

전역 카운터와 Source MAC별 카운터 모두 이 방식을 사용합니다.

### Per-Source MAC Statistics
Source MAC별 통계는 **Deauthentication 프레임을 보낸 송신자별로 따로 카운트**합니다.

즉:
- 전체 Deauth 이벤트 전역 카운터 유지
- `source MAC -> recent events queue` 형태의 per-source 통계 유지

가능하면 아래 통계도 함께 유지합니다.
- 최근 윈도우 내 count
- 누적 total count
- 마지막 발생 시각
- 마지막 alert 발생 시각

### Alert Severity Policy
임계치는 고정 단일값이 아니라 **단계형(threshold tiers)** 으로 구현합니다.

최소 아래 3단계를 지원합니다.
- `info`
- `warn`
- `critical`

기본 예시 정책(초기값, 필요 시 기존 코드 스타일에 맞게 조정 가능):
- global info: 최근 10초 동안 deauth count >= 10
- global warn: 최근 10초 동안 deauth count >= 20
- global critical: 최근 10초 동안 deauth count >= 40

- per-source info: 최근 10초 동안 동일 source MAC count >= 5
- per-source warn: 최근 10초 동안 동일 source MAC count >= 10
- per-source critical: 최근 10초 동안 동일 source MAC count >= 20

---

## Channel Hopping Requirements

### Objective
센서는 여러 채널을 순차적으로 순회하며 패킷을 수집할 수 있어야 합니다.  
채널 호핑 기능은 가능한 한 **기존 802.11 파서 및 캡처 코드 구조에 맞게** 통합되어야 합니다.

### Channel Hopping Rules
- 채널 목록은 설정 가능한 구조로 관리합니다.
- 센서는 지정된 순서대로 채널을 변경합니다.
- 각 채널에서 일정 시간(dwell time) 동안 머문 후 다음 채널로 이동합니다.
- 기존 코드에 채널 변경 함수 또는 관련 인터페이스가 있다면 반드시 재사용합니다.
- 기존 코드에 채널 제어 기능이 없으면 최소 침습적으로 확장합니다.

### Initial Default Policy
초기 기본 채널 정책 예시:
- 2.4GHz 채널 우선
  - 1, 6, 11
또는
  - 1∼13 전체 순환

실제 구현 시에는 기존 코드 구조와 운용 방식에 맞는 기본값을 선택합니다.

### Dwell Time
채널별 체류 시간(dwell time)은 설정 가능해야 합니다.

예시:
- 200ms
- 500ms
- 1000ms

기본값은 기존 코드 구조와 실제 센서 운용에 맞는 값으로 정하되,  
하드코딩보다 설정 가능한 상수/옵션 형태를 선호합니다.

### Channel Control Integration
작업 시작 시 반드시 기존 코드에서 아래를 확인합니다.

- 이미 채널 변경 함수 또는 인터페이스가 존재하는가
- OS/driver 호출 래퍼가 있는가
- 외부 툴 호출 방식인지, 내부 API 방식인지
- 캡처 스레드와 채널 변경 로직이 어떻게 상호작용해야 하는가

기존 방식이 있다면 반드시 재사용합니다.

### TODO for Channel Hopping
다음 항목은 기존 코드 분석 후 필요 시 TODO로 남길 수 있습니다.
- 드라이버/OS 의존 채널 변경 구현 세부화
- 권한 문제 처리
- 인터페이스 상태 점검
- 멀티밴드 지원 확장
- 지역별 채널 정책 반영

---

## Integration Requirements

### Deauth Detection Integration
1. 기존 802.11 파서가 Deauthentication 프레임을 식별하고 파싱
2. 파싱 결과에서 아래 정보를 탐지 모듈에 전달
   - timestamp
   - source MAC
   - destination MAC
   - BSSID
   - RSSI (optional)
   - reason code (if available)
3. 탐지 모듈은 해당 정보를 바탕으로 슬라이딩 윈도우 갱신
4. 임계치 초과 시 Alert 객체 또는 이벤트 생성

### Channel Hopping Integration
1. 기존 캡처 시작 지점 또는 센서 런타임 루프 확인
2. 채널 호핑 관리 객체 또는 루프를 연결
3. 지정한 dwell time마다 채널 변경
4. 채널 변경 상태를 로깅 또는 상태값으로 관리
5. 기존 캡처 흐름이 끊기지 않도록 주의

---

## Suggested Internal Structures
기존 코드 스타일을 우선 따르되, 아래와 유사한 구조를 고려할 수 있습니다.

### Detection
- `DeauthEvent`
- `DeauthFloodDetector`
- `DeauthSourceStats`
- `Alert`
- `AlertSeverity`

### Channel Hopping
- `ChannelHopper`
- `ChannelHopConfig`
- `ChannelState`
- `setChannel(...)`
- `nextChannel()`

단, 실제 타입과 네이밍은 반드시 기존 코드 스타일을 우선합니다.

---

## Coding Style
반드시 기존 **802.11 파서 코드의 스타일**을 우선적으로 따릅니다.

추가 원칙:
- C++다운 방식으로 구현
- C 스타일보다 현대적이고 안전한 C++ 우선
- 불필요한 전역 상태 금지
- raw pointer 남용 금지
- 가능하면 `std::deque`, `std::unordered_map`, `std::optional`, `std::vector`, `std::string` 등을 적절히 활용
- 파싱 코드와 탐지 코드의 책임 분리
- 채널 제어 로직과 패킷 파싱 로직 분리
- 하드코딩 최소화
- 임계치, 윈도우 크기, 채널 목록, dwell time은 상수/설정값으로 관리

---

## Safety and Robustness
- 잘못된 MAC 문자열이나 비어 있는 source MAC 입력에 안전하게 대응합니다.
- timestamp 역전 또는 비정상 입력이 들어와도 최대한 안전하게 처리합니다.
- 큐 정리 로직이 누락되어 메모리가 계속 증가하지 않도록 합니다.
- 잘못된 채널 값 또는 빈 채널 리스트에 안전하게 대응합니다.
- 채널 변경 실패 시 적절히 로그 또는 오류 상태를 남깁니다.
- alert 반복 생성 방지를 위해 필요하면 cooldown 로직을 고려할 수 있습니다.
- 단, cooldown이 기존 구조와 맞지 않으면 TODO 또는 확장 포인트로 남겨도 됩니다.

---

## Build Requirements
- 새로 추가한 소스/헤더 파일은 기존 빌드 시스템(CMake 등)에 반드시 반영합니다.
- 기존 빌드를 깨지 않도록 최소 침습적으로 수정합니다.
- 가능하면 `builds/` 디렉토리 기준으로 빌드 가능한 상태를 유지합니다.

---

## Expected Outcome
최종 결과물은 아래를 포함해야 합니다.

1. 기존 802.11 파서 코드 구조 분석 결과
2. 기존 코드 구조에 맞춘 Deauth Flood 탐지 모듈 설계
3. 슬라이딩 윈도우 기반 카운터 구현
4. Source MAC별 통계 구현
5. 단계형 Alert severity 구현 (`info`, `warn`, `critical`)
6. 기존 코드 구조에 맞춘 Channel Hopping 기능 구현
7. 채널 목록 및 dwell time 설정 구조
8. 필요한 CMake/빌드 파일 수정
9. 사용 방법 또는 테스트 방법 설명
10. TODO 항목 정리
   - OS/driver 의존 채널 제어 세부 구현 필요 사항

---

## Output Format
작업 결과는 아래 형식으로 정리합니다.

1. 기존 802.11 파서 코드 분석 요약
2. Deauth 탐지 통합 설계 요약
3. 채널 호핑 통합 설계 요약
4. 추가/수정 파일 목록
5. 구현 코드
6. 빌드 반영 사항
7. 테스트 또는 검증 방법
8. TODO 항목 정리

---

## Explicit Instructions
반드시 아래 원칙을 지킵니다.

- 먼저 기존 802.11 파서 코드를 읽고 구조를 분석할 것
- 기능 추가는 반드시 기존 802.11 파서 코드 구조에 맞춰 진행할 것
- 새 파서를 따로 만들지 말 것
- 기존 코드 스타일과 구조를 우선적으로 따를 것
- Deauth Flood 탐지 모듈은 기존 코드에 확장 형태로 추가할 것
- 슬라이딩 윈도우는 timestamp queue 방식으로 구현할 것
- Source MAC별 통계는 deauth를 보낸 송신자 기준으로 집계할 것
- Alert severity는 `info`, `warn`, `critical` 단계형으로 구현할 것
- 채널 호핑 기능을 기존 캡처 흐름에 맞게 통합할 것
- 채널 목록과 dwell time은 설정 가능한 구조로 둘 것
- 기존 코드에 채널 제어 기능이 있으면 반드시 재사용할 것
- 파서 로직, 탐지 로직, 채널 제어 로직은 분리할 것
- C++다운 방식으로 구현할 것