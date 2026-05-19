#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>

// 802.11 Tagged Parameter 하나에 대한 non-owning 뷰.
// 원본 캡처 버퍼를 직접 가리키므로 별도 메모리 할당이 없다.
//
// 와이어 포맷: [num : 1바이트][len : 1바이트][data : len바이트]
//   예) SSID "hi" → [0x00][0x02][0x68][0x69]
//   예) CSA       → [0x25][0x03][mode][ch][count]
struct TagView {
    uint8_t        num;   // 태그 번호 (0=SSID, 37=CSA, 60=ECSA, ...)
    uint8_t        len;   // data 필드 바이트 수 (0이면 data는 없음)
    const uint8_t* data;  // 원본 버퍼 내 data 시작 포인터 (len바이트)

    // [num][len][data...] 순서로 out 끝에 복사한다.
    void appendTo(std::vector<uint8_t>& out) const {
        out.push_back(num);
        out.push_back(len);
        out.insert(out.end(), data, data + len);
    }
};

// TLV 스트림 전체를 앞에서 뒤로 순회하며 각 태그에 대해 f(TagView)를 호출한다.
//
//   i + 2 <= tagsLen : num·len 두 바이트를 읽을 공간이 남아 있는지 매 반복 확인
//   next = i + 2 + len : 다음 태그의 시작 인덱스
//
//   f(TagView) → bool:
//     true  : 다음 태그로 계속 진행
//     false : 즉시 순회 중단 (원하는 태그를 찾은 후 조기 종료하는 용도)
//
//   next > tagsLen : len이 남은 버퍼를 초과 → 손상 TLV로 판단하고 안전 종료
template<typename Fn>
inline void scan_tags(const uint8_t* tags, size_t tagsLen, Fn f) {
    for (size_t i = 0; i + 2 <= tagsLen; ) {
        uint8_t len  = tags[i + 1];
        size_t  next = i + 2 + len;
        if (next > tagsLen) break;                           // 손상 TLV — 안전 종료
        if (!f(TagView{tags[i], len, tags + i + 2})) break;  // 콜백 false → 조기 종료
        i = next;
    }
}
