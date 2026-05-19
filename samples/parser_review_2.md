# `src/parser.cpp` 코드 비평 — Round 2

대상: 1차 비평([parser_review.md](./parser_review.md)) 이후 일부 항목 반영, 일부 의도적 미반영(헬퍼 구조 제거)된 현재 상태.
반영 상태 요약: 1.1, 1.2, 1.5, 2.4, 3.3 반영. 2.1, 3.1 의도적 미반영(인라인 선호).

---

## 1. 1차 비평 중 아직 남아 있는 항목

### 1.1 확장 present 워드 namespace 가정 (1차 §1.3 유지)
`extract_rssi`는 확장 워드를 건너뛴 뒤에도 *첫 번째 present 워드*의 비트로 필드를 해석한다. 표준 namespace에서는 맞지만, 확장 워드가 새 namespace를 정의하는 경우(예: vendor namespace) 비트 의미가 달라진다. 실측 캡처에서 DBM_SIGNAL을 못 찾는 false-negative가 가끔 생길 수 있다.

### 1.2 엔디안 처리 부재 (1차 §1.4 유지)
`frameControl`, `seqCtrl`, `it_present`, `it_len`, beacon timestamp 등은 wire에서 LE. 호스트 LE를 묵시 가정한다. x86/Windows·ARM-LE에서는 무해하지만 BE 플랫폼에서 즉시 깨진다.

### 1.3 `frameType`이 `std::string` (1차 §2.2 유지)
"Beacon", "ProbeReq", "Deauth" 등 7가지 리터럴 중 하나가 들어갈 뿐인데 매번 string 객체를 만든다. SSO 안에 들어가니 동적 할당은 보통 없지만, 비교/스위치 처리 시 비효율적이고 의미적으로도 `enum class`가 적합하다.

### 1.4 `rssi`/`hasRssi` 두 필드 (1차 §4 유지)
헤더에 `int8_t rssi = 0; bool hasRssi = false;` 두 필드가 있어, 호출 측이 *"hasRssi 가 false면 rssi를 보지 말 것"* 이라는 invariant를 손으로 지켜야 한다. `std::optional<int8_t>` 로 합치면 컴파일러가 강제한다. (`hasSsid` 도입 후에는 같은 패턴이 SSID 쪽에도 있음 → §3.2 참고.)

### 1.5 `parse_mgmt_frame` 실패 원인 구분 불가 (1차 §4 유지)
`std::nullopt` 하나로 *비관리 프레임*, *truncated*, *unknown subtype* 이 합쳐진다. 디버깅·통계 단계에서 enum 결과가 유용.

### 1.6 PCH 의존 (1차 §4 유지)
`<cstring>`, `<string>`, `<optional>` 모두 `pch.h` 가 가져다주는 것에 의존. 명시적 include가 안전.

---

## 2. 새로 보이는 항목

### 2.1 `typeName` 임시 변수가 군더더기
`std::string typeName = "Beacon"; ... result.frameType = typeName;` — 두 번 복사가 일어난다. 첫 switch에서 바로 `result.frameType = "Beacon";` 형태로 대입해도 같다. ParsedFrame을 일찍 만들어두면 임시변수가 필요 없어진다.

```cpp
ParsedFrame result;
switch (frameSubtype) {
    case MGMT_SUBTYPE_BEACON:     result.frameType = "Beacon";    break;
    ...
    default: return std::nullopt;
}
```

`default: return std::nullopt;`가 switch 안에 있으므로 ParsedFrame을 미리 만들어두는 비용은 unknown subtype에서만 발생하는데, 이건 frameType 체크 이후라 빈도가 낮다. 거의 비용 없음.

### 2.2 두 switch 사이의 invariant가 컴파일러 검증 안 됨
첫 번째 switch는 unknown subtype을 `default: return std::nullopt`로 거른다. 두 번째 switch는 default 가 없는데, 첫 번째에서 이미 걸렀다는 *전제* 에 의존한다. 새 서브타입을 첫 번째에만 추가하고 두 번째에는 누락하면 `fixedLen = 0` 으로 떨어져 잘못된 tagsStart가 나온다.

방어책 한 줄: 두 번째 switch 끝에도 `default: return std::nullopt;` 또는 `default: assert(false);` 를 두면 두 switch가 동기화 안 됐을 때 조용히 잘못 동작하지 않는다.

### 2.3 `hasSsid` 가 main.cpp에 반영 안 됨
`ParsedFrame::hasSsid` 를 추가했지만 `src/main.cpp:19` 는 여전히 `if (!f.ssid.empty())` 만 본다. 결과적으로 hidden SSID (`hasSsid=true, ssid=""`) 가 출력되지 않아 1.5(1차 §1.5) 도입의 의도가 화면까지 전달되지 않는다.

```cpp
if (f.hasSsid) {
    if (f.ssid.empty()) std::cout << "  ssid=<hidden>";
    else                std::cout << "  ssid=\"" << f.ssid << "\"";
}
```

### 2.4 `alignTo(cursor, 8)` 의 8은 매직 넘버
바로 옆에서 `sizeof(uint64_t)` 를 쓰고 있는데, 정렬 단위만 raw 8 이다. `alignTo(cursor, alignof(uint64_t))` 또는 단순히 `8 /* TSFT align */` 주석. CHANNEL의 `alignTo(cursor, 2)` 도 마찬가지.

### 2.5 `extract_rssi` 의 5개 if 블록이 거의 같은 모양
구조적 헬퍼(테이블) 도입은 의도적으로 거부했지만, *함수 안에서* 람다 한 줄로 묶을 수는 있다 — 외부에 식별자를 노출하지 않으면서 중복을 줄이는 절충안.

```cpp
auto skip = [&](size_t align, size_t size) -> bool {
    cursor = Dot11RadioTap::alignTo(cursor, align);
    if (cursor + size > rtLen) return false;
    cursor += size;
    return true;
};

if ((present & Dot11RadioTap::PRESENT_TSFT)    && !skip(8, sizeof(uint64_t)))         return false;
if ((present & Dot11RadioTap::PRESENT_FLAGS)   && !skip(1, 1))                        return false;
if ((present & Dot11RadioTap::PRESENT_RATE)    && !skip(1, 1))                        return false;
if ((present & Dot11RadioTap::PRESENT_CHANNEL) && !skip(2, 2 * sizeof(uint16_t)))     return false;
if ((present & Dot11RadioTap::PRESENT_FHSS)    && !skip(1, sizeof(uint16_t)))         return false;
```

5줄짜리 비트별 처리가 한 줄씩으로 줄고, 새 필드를 추가해도 같은 한 줄. 파일 상단에 별도 구조체가 생기지 않아 1차 비평의 §3.1 우려도 안 생긴다.

### 2.6 `if (rtLen > len) return std::nullopt;`
RadioTap 헤더가 자기 길이를 거짓말한 경우(`it_len > 캡처된 길이`)를 거른다. 정상이지만 `rtLen >= sizeof(Dot11RadioTap)` 와 `rtLen <= len` 두 조건을 한 줄에 묶어두면 wire-trust 경계가 더 또렷하다. 미세.

### 2.7 `extract_ssid` 가 첫 SSID 태그만 본다
802.11에서 합법적인 동작이지만, *deauth attack* 류에서는 잘못된 SSID 태그가 끼어들 수 있다. 현재 코드는 "처음 만난" 태그를 SSID 로 채택. 정상 트래픽에서는 무해.

---

## 3. 우선순위 (Round 2)

| 우선순위 | 항목 | 위치 |
|---|---|---|
| 높음 | 2.2 두 switch 동기화 가드 (`default: return nullopt`) | parser.cpp:110~144 |
| 높음 | 2.3 main.cpp 출력이 `hasSsid` 반영 | main.cpp:19~20 |
| 중간 | 1.4 `rssi/hasRssi` → `std::optional<int8_t>` (그리고 `ssid/hasSsid` 도) | mgmt_parser.h |
| 중간 | 2.5 람다로 5줄 인라인 정리 (인라인 스타일 유지) | parser.cpp:38~58 |
| 낮음 | 1.3 `frameType` 을 enum class 로 | mgmt_parser.h, parser.cpp |
| 낮음 | 2.1 `typeName` 임시 변수 제거 | parser.cpp:106~118 |
| 낮음 | 1.5 parse 실패 원인 enum | mgmt_parser.h |
| 낮음 | 2.4 align 매직 넘버 | parser.cpp:38, 50 |
| 낮음 | 1.1 확장 namespace, 1.2 엔디안, 1.6 PCH 의존 | parser.cpp, dot11.h |

전반적으로 1차 비평의 정확성 이슈(경계 검사, hidden SSID 구분)는 해소되었고, 남은 것은 대부분 **invariant를 코드/타입으로 강제할 것인가, 관행으로 둘 것인가**의 문제. 그중 §2.2(두 switch 동기화)와 §2.3(main 출력)은 *현재 동작에 직접 영향*을 주므로 우선 처리 추천.
