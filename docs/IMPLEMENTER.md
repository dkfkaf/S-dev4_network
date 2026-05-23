# IMPLEMENTER.md

## Role
당신의 역할은 **구현자(implementer)** 입니다.  
기존 802.11 파서 코드를 읽고, 기존 구조와 스타일을 유지하면서  
**Deauth Flood 탐지 모듈**과 **채널 호핑 기능**을 추가 구현합니다.

---

## Mandatory First Step
반드시 먼저 아래를 수행합니다.

1. 기존 802.11 파서 코드 구조 분석
2. 현재 패킷 처리 흐름 분석
3. Deauthentication 프레임이 어디서 파싱되고 어떤 결과 구조로 전달되는지 확인
4. 캡처 루프와 채널 제어 관련 코드가 이미 존재하는지 확인
5. 기존 네이밍, 클래스/구조체 설계, 로깅, 빌드 구조 파악
6. 새 기능을 기존 코드 구조에 어떻게 통합할지 먼저 정리

---

## Main Objective
다음 두 가지 기능을 구현합니다.

### 1. Deauth Flood Detection
기존 파서가 추출한 Deauthentication 프레임 정보를 활용하여  
**Deauth Flood 탐지 모듈**을 구현합니다.

요구사항:
- 슬라이딩 윈도우 카운터 사용
- 타임스탬프 큐 방식 구현
- 전역 카운터 유지
- Source MAC별 통계 유지
- 단계형 Alert severity 지원
  - `info`
  - `warn`
  - `critical`

### 2. Channel Hopping
기존 캡처 흐름에 맞춰 **채널 호핑 기능**을 구현합니다.

요구사항:
- 채널 목록 설정 가능
- dwell time 설정 가능
- 순차적 채널 변경
- 기존 채널 제어 함수가 있으면 재사용
- 없으면 최소 침습적으로 확장

---

## Implementation Rules

### Deauth Sliding Window
슬라이딩 윈도우는 반드시 **timestamp queue** 방식으로 구현합니다.

원칙:
- 이벤트가 들어오면 timestamp push
- 윈도우 밖 timestamp 제거
- queue size를 최근 count로 사용

이 원칙은:
- global deauth count
- per-source deauth count

모두에 적용합니다.

### Per-Source Statistics
Source MAC별 통계는 **Deauthentication 프레임을 보낸 송신자 기준**으로 집계합니다.

가능하면 아래 정보도 유지합니다.
- recent window count
- total count
- last seen timestamp
- last alert timestamp

### Threshold Policy
임계치는 반드시 단계형으로 구현합니다.

기본 목표:
- `info`
- `warn`
- `critical`

기본 예시값:
- global info: 10초 / 10개 이상
- global warn: 10초 / 20개 이상
- global critical: 10초 / 40개 이상

- per-source info: 10초 / 5개 이상
- per-source warn: 10초 / 10개 이상
- per-source critical: 10초 / 20개 이상

실제 상수 이름과 배치는 기존 코드 스타일에 맞춥니다.

### Channel Hopping
채널 호핑은 기존 코드 구조에 맞춰 구현합니다.

원칙:
- 채널 목록은 설정 가능한 구조 사용
- dwell time은 설정 가능해야 함
- 채널 변경 로직은 캡처 루프와 충돌하지 않도록 설계
- 기존 채널 제어 함수가 있으면 반드시 재사용
- 채널 제어 함수가 없으면 최소 범위로 추가

기본 예시 정책:
- 2.4GHz 기준 `1, 6, 11` 또는 `1∼13`
- dwell time 예시: `200ms`, `500ms`, `1000ms`

---

## Integration Rules
기존 코드에 아래 흐름으로 통합합니다.

### Deauth Detection Integration
1. 기존 파서가 Deauthentication frame을 파싱
2. source MAC / destination MAC / BSSID / RSSI / reason code / timestamp 확보
3. 탐지 모듈에 이벤트 전달
4. 탐지 모듈이 카운터 갱신
5. 임계치 초과 시 alert 생성

### Channel Hopping Integration
1. 기존 캡처 시작 지점 또는 런타임 루프 확인
2. 채널 호핑 관리 로직 연결
3. dwell time마다 채널 변경
4. 채널 변경 상태 로깅 또는 상태값 반영

주의:
- 파서에서 flood 판단까지 직접 하지 않습니다.
- 파서, 탐지, 채널 제어의 책임을 분리합니다.

---

## Coding Instructions
- 반드시 기존 802.11 파서 코드 스타일 우선
- C++다운 방식으로 작성
- `std::deque`, `std::unordered_map`, `std::optional`, `std::vector` 등을 적절히 활용
- 하드코딩 최소화
- 잘못된 source MAC 입력에 안전하게 대응
- 빈 채널 리스트나 잘못된 dwell time에 안전하게 대응
- 채널 변경 실패 시 로그 또는 오류 상태 처리

---

## Output Format
작업 결과는 아래 순서로 제시합니다.

1. 기존 파서 코드 분석 요약
2. Deauth 탐지 통합 포인트 설명
3. 채널 호핑 통합 포인트 설명
4. 설계 요약
5. 추가/수정 파일 목록
6. 구현 코드
7. CMake/빌드 반영 사항
8. 테스트 또는 검증 방법
9. TODO 정리
   - OS/driver 의존 채널 제어 세부 사항

---

## Constraints
- 기존 파서를 갈아엎지 말 것
- 과도한 리팩토링 금지
- 빌드 깨뜨리는 변경 금지
- 불필요한 신규 추상화 남발 금지
- 설명만 하지 말고 실제 코드 중심으로 제시

---

## Quality Bar
구현 결과는 아래를 만족해야 합니다.

- 기존 구조와 자연스럽게 통합됨
- timestamp queue 기반 sliding window 구현 완료
- source MAC별 통계 구현 완료
- 단계형 alert severity 구현 완료
- 채널 호핑 기능 구현 완료
- 빌드 가능성 높음