#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>
#include "dot11.h"

// 태그 구조체(src)를 바이트 단위로 out 끝에 붙인다.
inline void append_tag(std::vector<uint8_t>& out, const void* src, size_t size) {
    const uint8_t* p = static_cast<const uint8_t*>(src);
    out.insert(out.end(), p, p + size);
}

// 기존 Tagged Parameters에서 CSA/ECSA를 제거하고,
// 태그 번호 오름차순을 유지하며 새 csa/ecsa를 올바른 위치에 삽입한다.
//
// 802.11 태그는 메모리에 항상 이 구조로 나열된다:
//   [num(1바이트)][len(1바이트)][data(len바이트)] [num][len][data] ...
//   예) [37][3][AA][BB][CC][40][2][DD][EE]
//        0   1  2   3   4   5   6  7   8
//
//   tags[i]     = 태그 번호 (num)
//   tags[i+1]   = 데이터 크기 (len)
//   next_tagIdx = i + 2 + len → 다음 태그가 시작되는 인덱스
//   i = next_tagIdx 로 이동하면 다음 태그로 넘어간다.
//   i + 2 <= tagsLen : 번호+길이 읽을 공간(최소 2칸)이 남아있는지 확인
inline void insert_tag_in_capture(
    std::vector<uint8_t>&  out,
    const uint8_t*         tags,
    size_t                 tagsLen,
    const Beacon::CsaTag&  csa,
    const Beacon::EcsaTag& ecsa)
{
    bool csaInserted  = false;
    bool ecsaInserted = false;

    for (size_t i = 0; i + 2 <= tagsLen; ) {
        uint8_t num         = tags[i];      // 태그 번호
        uint8_t len         = tags[i + 1];  // 데이터 크기
        size_t  next_tagIdx = i + 2 + len;  // 다음 태그 시작 인덱스

        if (next_tagIdx > tagsLen) break;  // 손상된 TLV 방어

        if (num == 37 || num == 60) { i = next_tagIdx; continue; }  // 기존 CSA/ECSA는 out에 담지 않고 건너뜀

        // 현재 태그보다 번호가 작은 CSA/ECSA를 먼저 삽입해 정렬 유지
        if (!csaInserted  && num >= 37) { append_tag(out, &csa,  sizeof(csa));  csaInserted  = true; }
        if (!ecsaInserted && num >= 60) { append_tag(out, &ecsa, sizeof(ecsa)); ecsaInserted = true; }

        const uint8_t* tagStart = tags + i;
        const uint8_t* tagEnd   = tags + next_tagIdx;
        out.insert(out.end(), tagStart, tagEnd);  // 기존 태그 한 개 복사
        i = next_tagIdx;
    }

    // 삽입 위치를 못 찾은 태그는 맨 뒤에 추가
    if (!csaInserted)  append_tag(out, &csa,  sizeof(csa));
    if (!ecsaInserted) append_tag(out, &ecsa, sizeof(ecsa));
}
