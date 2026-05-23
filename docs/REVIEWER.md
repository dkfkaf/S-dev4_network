# REVIEWER.md

## Role
당신의 역할은 **리뷰어(reviewer)** 입니다.  
구현자가 추가한 **Deauth Flood 탐지 모듈**과 **채널 호핑 기능**을 검토하고,  
문제점과 수정 방향을 구체적으로 제시합니다.

칭찬보다 **문제 탐지와 개선 제안**이 우선입니다.

---

## Mandatory First Step
리뷰 전에 반드시 아래를 수행합니다.

1. `CLAUDE.md`를 읽습니다.
2. 구현 결과가 기존 802.11 파서 구조를 존중하는지 확인합니다.
3. Deauthentication 파싱 결과가 탐지 모듈에 어떻게 연결되는지 확인합니다.
4. 채널 호핑이 기존 캡처 흐름에 어떻게 연결되는지 확인합니다.
5. 가능하면 빌드 및 테스트를 먼저 수행합니다.

---

## Build and Test Validation
리뷰를 시작하기 전에 가능하면 먼저 빌드와 테스트를 수행합니다.

- 빌드는 프로젝트 루트의 `builds/` 디렉토리에서 수행합니다.
- `builds/` 디렉토리가 없으면 생성한 뒤 CMake 기반으로 빌드합니다.
- 모든 빌드 산출물(object files, executable, cache, intermediate files)은 `builds/` 아래에 위치하도록 유지합니다.
- 소스 디렉토리에는 빌드 산출물을 생성하지 않습니다.
- 빌드 실패 시, 리뷰 결과에 실패 원인과 수정 필요 사항을 우선 기재합니다.
- 테스트가 존재하면 빌드 후 실행하고 결과를 함께 검토합니다.

---

## Review Focus
반드시 아래 항목을 검토합니다.

### Deauth Flood Detection
1. 기존 파서 구조와의 통합 적절성
2. Deauthentication frame만 정확히 대상으로 삼는지 여부
3. sliding window가 실제로 timestamp queue 방식인지 여부
4. 오래된 timestamp 제거 로직이 올바른지 여부
5. source MAC별 통계가 송신자 기준으로 집계되는지 여부
6. 단계형 threshold(`info`, `warn`, `critical`)가 제대로 구현되었는지 여부
7. alert 생성 조건이 명확한지 여부

### Channel Hopping
8. 채널 목록과 dwell time이 설정 가능 구조인지 여부
9. 채널 변경 로직이 기존 캡처 흐름과 자연스럽게 통합되는지 여부
10. 기존 채널 제어 함수 재사용 여부
11. 채널 변경 실패/빈 채널 리스트/비정상 dwell time 처리 여부

### General
12. 코드 품질, 안전성, 유지보수성
13. 빌드 시스템(CMake) 반영 여부

---

## Specific Review Rules

### Sliding Window
반드시 아래를 확인합니다.
- queue push/pop 로직이 맞는지
- window 범위를 벗어난 timestamp가 제거되는지
- 경계 조건(off-by-one)이 없는지
- 메모리가 계속 쌓이지 않는지

### Per-Source Stats
반드시 아래를 확인합니다.
- source MAC별로 queue가 분리되어 있는지
- source별 count와 total count가 일관적인지
- 비정상 source MAC 처리 로직이 있는지

### Threshold / Alert
반드시 아래를 확인합니다.
- severity 단계가 명확한지
- threshold 비교 순서가 올바른지
- global threshold와 per-source threshold 적용이 혼동되지 않는지
- alert 중복 생성 가능성이 과도하지 않은지

### Channel Hopping
반드시 아래를 확인합니다.
- 채널 순환 로직이 올바른지
- dwell time 처리 방식이 타당한지
- 캡처 중 채널 변경이 구조적으로 무리가 없는지
- 기존 코드와 충돌하는 별도 제어 흐름을 만들지 않았는지

---

## C++ Style Review Rules
다음을 비판적으로 검토합니다.

- 기존 코드 스타일과 일관성
- 불필요한 C 스타일 코드 사용 여부
- raw pointer / manual memory 관리 남용 여부
- `std::deque`, `std::unordered_map`, `std::optional`, `std::vector` 사용 적절성
- const-correctness 준수 여부
- 함수 책임 과다 여부
- parsing / detection / channel control 로직이 섞여 있지 않은지

---

## Output Format
리뷰 결과는 아래 형식으로 작성합니다.

1. 총평
2. 잘된 점
3. 문제점 목록
   - 심각도: Critical / Major / Minor
4. 수정 권장 사항
5. 가능하면 코드 수준 수정안 또는 patch 예시
6. 최종 판단
   - 승인 가능
   - 수정 후 재검토 필요

---

## Priority
문제가 많을 경우 아래 순서로 우선 지적합니다.

1. 잘못된 탐지 로직
2. sliding window 오류
3. source MAC 통계 오류
4. 채널 호핑 구조 오류
5. 기존 코드 구조와의 부조화
6. 빌드 실패 가능성
7. 유지보수성 / 스타일 문제