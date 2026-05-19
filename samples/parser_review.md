# `src/parser.cpp` 코드 비평

대상: `src/parser.cpp` (의존: `include/dot11.h`, `include/tag.h`, `include/mgmt_parser.h`)
범위: 정확성, 경계 검사, 가독성, 설계 일관성, 휴대성.

---

## 1. 정확성 / 안전성

### 1.1 `extract_rssi`의 경계 검사가 "off-by-something"
필드 크기와 비교 부등호가 일관되지 않는다.

```cpp
if (cursor > rtLen) return false;     // RATE 직전·CHANNEL 직전 등
...
if (cursor >= rtLen) return false;    // RSSI 1바이트 읽기 직전
```

엄밀하게는 *"앞으로 N바이트를 읽기 전에 N바이트가 남아 있는가"* 를 검사해야 한다. 현재 코드는 cursor만 늘려놓고 다음 검사로 미루는 패턴이라, 비트가 켜져 있는 필드의 데이터를 실제로 읽지 않으면서 cursor만 누적된다. RSSI 1바이트 직전에 한 번에 잡히긴 하지만, 의미적으로는 다음 형태가 더 명확하다.

```cpp
auto need = [&](size_t n) { return cursor + n <= rtLen; };

if (present & Dot11RadioTap::PRESENT_TSFT) {
    cursor = Dot11RadioTap::alignTo(cursor, 8);
    if (!need(sizeof(uint64_t))) return false;
    cursor += sizeof(uint64_t);
}
...
if (!need(1)) return false;
rssiOut = static_cast<int8_t>(rtBuf[cursor]);
```

### 1.2 CHANNEL 필드 크기에 매직 넘버
다른 필드는 `sizeof(uint64_t)`, `sizeof(uint32_t)`로 표현하는데 CHANNEL만 `cursor += 4;` 라는 raw 4가 박혀 있다. 의미는 `uint16_t frequency + uint16_t flags`. 상수화하거나 주석에 의도 분해를 적어두는 게 좋다.

### 1.3 확장 present 워드의 namespace 가정
`extract_rssi`는 확장 present 워드를 건너뛴 뒤에도 *첫 번째 워드*의 비트로만 필드를 해석한다. 표준 namespace에서는 맞지만, 확장 워드가 새로운 namespace(예: vendor namespace)를 정의하는 경우 비트 의미가 다르다. 현재 주석에 "표준 namespace만 본다"라고 명시되어 있어 의도된 단순화이지만, 실제 무선 캡처에서 DBM_SIGNAL을 못 찾는 false negative가 종종 발생할 수 있다. 안정성을 더 원하면 표준 namespace 워드를 별도로 추적해 그 비트에서만 DBM_SIGNAL을 읽어야 한다.

### 1.4 엔디안 처리 부재
`frameControl`, `seqCtrl`, `it_present`, `it_len`, beacon timestamp 등은 wire에서 little-endian으로 들어온다. 코드는 호스트 LE를 묵시 가정한다. x86/ARM-LE에서는 문제없지만, BE 플랫폼으로 옮기면 즉시 깨진다. `letoh16/32` 류 래퍼를 두는 편이 안전하다.

### 1.5 `hidden SSID` 구분 불가
태그 0의 `len == 0` 인 경우와 *SSID 태그가 아예 없는 경우* 가 모두 `ssid == ""` 로 합쳐진다. `ParsedFrame`에 `bool hasSsid` 가 있으면 IDS 관점에서 hidden vs missing을 구분할 수 있다.

---

## 2. 설계 / 일관성

### 2.1 동일한 `frameSubtype`에 대한 switch 두 번
`parse_mgmt_frame` 안에서 동일한 `frameSubtype` 값으로 switch를 두 번 한다. typeName과 fixedLen이 한 쌍이므로 lookup 테이블 하나로 합치는 게 자연스럽다.

```cpp
struct SubtypeInfo { const char* name; size_t fixedLen; };

constexpr auto info_of = [](uint8_t s) -> std::optional<SubtypeInfo> {
    switch (s) {
        case MGMT_SUBTYPE_BEACON:     return SubtypeInfo{"Beacon",    sizeof(Beacon)};
        case MGMT_SUBTYPE_PROBE_RESP: return SubtypeInfo{"ProbeResp", sizeof(Beacon)};
        case MGMT_SUBTYPE_PROBE_REQ:  return SubtypeInfo{"ProbeReq",  0};
        case MGMT_SUBTYPE_DEAUTH:     return SubtypeInfo{"Deauth",    sizeof(Deauth)};
        case MGMT_SUBTYPE_AUTH:       return SubtypeInfo{"Auth",      sizeof(Auth)};
        case MGMT_SUBTYPE_ASSOC_REQ:  return SubtypeInfo{"AssocReq",  sizeof(AssocReq)};
        case MGMT_SUBTYPE_ASSOC_RESP: return SubtypeInfo{"AssocResp", sizeof(AssocResp)};
    }
    return std::nullopt;
};
```

이렇게 하면 "지원 서브타입 체크 + 이름 + 고정 파라미터 길이"가 한 곳에 모이고, 새 서브타입을 추가할 때 두 곳을 동기화할 필요가 없다.

### 2.2 `frameType`이 `std::string`
프레임마다 7가지 짧은 리터럴 중 하나가 들어갈 뿐인데 매번 동적 할당(SSO 한계 16~22바이트라 보통 SSO 안에서 해결되긴 함)된다. `const char*` 또는 enum + `to_string` 헬퍼가 더 적절하다. 비교/스위치도 더 쉽다.

### 2.3 `Beacon` 구조체 안에 `CsaTag`/`EcsaTag` 내포
헤더 `dot11.h`의 `Beacon` 은 "Beacon fixed params" 라고 주석되어 있지만 그 안에 CSA/ECSA 태그 정의까지 들어가 있다. 파서가 다루는 영역과 관심사가 다르므로 분리하는 게 깔끔하다 (예: `csa_tags.h`). 현재 파일은 parser.cpp 이슈는 아니지만, parser가 의존하는 헤더의 관심사 분리가 어색하다.

### 2.4 RSSI 추출을 위해 RadioTap을 두 번 memcpy
`parse_mgmt_frame`이 한 번 memcpy하고, 내부에서 `extract_rssi`가 다시 memcpy한다. 작은 비용이지만, `extract_rssi(const Dot11RadioTap& rt, const uint8_t* rtBuf, size_t rtLen, int8_t& out)` 시그니처로 받아 처음 한 번만 복사하는 게 자연스럽다.

---

## 3. 가독성 / 스타일

### 3.1 누적식 cursor 패턴
`if (bit) cursor += N;` 가 줄줄이 늘어선 형태는 802.11 스펙을 모르는 독자에게 의도가 잘 안 보인다. 표 형태(필드 메타데이터 배열 → 루프)가 가독성을 크게 올린다.

```cpp
struct RtField {
    uint32_t presentBit;
    size_t   align;
    size_t   size;
};
constexpr RtField fields[] = {
    {Dot11RadioTap::PRESENT_TSFT,    8, 8},
    {Dot11RadioTap::PRESENT_FLAGS,   1, 1},
    {Dot11RadioTap::PRESENT_RATE,    1, 1},
    {Dot11RadioTap::PRESENT_CHANNEL, 2, 4},
    {Dot11RadioTap::PRESENT_FHSS,    1, 2},
};
for (auto& f : fields) {
    if (!(present & f.presentBit)) continue;
    cursor = Dot11RadioTap::alignTo(cursor, f.align);
    if (cursor + f.size > rtLen) return false;
    cursor += f.size;
}
// 이 자리가 DBM_SIGNAL
```

여기에 `hasFCS()` 도 정확히 같은 누적 패턴을 다시 구현하고 있어 중복이다. 공용 헬퍼로 뽑으면 두 곳이 같이 정리된다.

### 3.2 주석은 풍부하지만 코드는 그만큼 표현적이지 않다
주석으로 "bit 0 TSFT 8바이트, align 8" 식의 명세를 적어두는데, 실제 코드는 이 명세를 *런타임 로직*으로만 표현한다. 위 3.1의 데이터 테이블 형태가 "주석이 곧 코드" 가 되어 의도와 구현이 어긋날 여지를 없앤다.

### 3.3 `tagsStart <= frameEnd` 조건
경계 비교가 `<=` 인데, 실제로는 `tagsStart < frameEnd` 일 때만 의미가 있다 (같을 때는 `frameEnd - tagsStart == 0`이라 `extract_ssid`가 빈 문자열을 반환). 동작은 같지만 의도는 후자가 명확하다.

---

## 4. 작은 것들

- `result.hasRssi = extract_rssi(...)` 호출 시 RSSI를 못 찾으면 `result.rssi` 가 0으로 초기화된 값 그대로 남는다(헤더에 `int8_t rssi = 0`). `hasRssi == false` 이면 `rssi` 값을 보지 말아야 한다는 invariant를 호출 측이 지켜야 한다. `std::optional<int8_t>` 로 합치면 컴파일러가 강제할 수 있다.
- `parse_mgmt_frame`이 management frame이 아닐 때 `nullopt`를 반환하는데, 이건 "에러"가 아니라 "관심 없음" 이다. 호출자가 매번 nullopt를 보고 원인을 추측해야 한다. 디버깅 단계에서는 enum 결과(`NotMgmt`, `Truncated`, `UnknownSubtype`, `Ok`)가 유용하다.
- `parser.cpp` 헤더 `#include <cstring>` 가 누락되어 있지만 `pch.h` 가 가져다주는 것에 의존한다. PCH 의존을 줄이려면 명시적으로 include하는 편이 안전.

---

## 5. 우선순위 요약

| 우선순위 | 항목 | 위치 |
|---|---|---|
| 높음 | RSSI 경계 검사 일관화 (`cursor + N <= rtLen`) | parser.cpp:40~61 |
| 높음 | 두 번 switch → lookup 테이블 1회 | parser.cpp:108~144 |
| 중간 | RadioTap 필드 파싱을 데이터 테이블 + 공용 헬퍼로 통합 (`extract_rssi` ↔ `hasFCS`) | parser.cpp:40~63, dot11.h:44~63 |
| 중간 | `rssi` → `std::optional<int8_t>` | mgmt_parser.h:15~16 |
| 낮음 | `frameType`을 `enum` 또는 `const char*` | mgmt_parser.h:10, parser.cpp:108~118 |
| 낮음 | `hasSsid` 플래그 분리 | mgmt_parser.h:14 |
| 낮음 | 엔디안 변환 명시화 | parser.cpp:100, dot11.h 전반 |

전반적으로 **정확성은 큰 무리 없이 동작하지만, 동일 정보(서브타입, RadioTap 비트 순서)를 코드 두 군데에서 반복하고 있어 유지보수 시 동기화 깨질 위험**이 가장 큰 약점이다.
