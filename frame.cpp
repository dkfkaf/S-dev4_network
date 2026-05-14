#include "frame.h"
#include "dot11.h"
#include <cstring>

static size_t append_tag(
    uint8_t*       dotframe,
    size_t         dotframeSize,
    size_t         dotnew_frame_end,
    const uint8_t* newTag,
    size_t         newTagSize)
{
    if (dotnew_frame_end + newTagSize > dotframeSize) return 0;
    std::memcpy(dotframe + dotnew_frame_end, newTag, newTagSize);
    return dotnew_frame_end + newTagSize;
}

size_t build_csa_beacon(
    uint8_t*       out_Buf,
    size_t         in_BufSize,
    const uint8_t* in_captured,
    size_t         in_capturedLen,
    bool           in_useUnicast,
    const Mac&     in_staMac)
{
    if (in_capturedLen < sizeof(Dot11RadioTap)) return 0;

    const Dot11RadioTap* rtHdr = reinterpret_cast<const Dot11RadioTap*>(in_captured);
    size_t rtLen = rtHdr->len();
    if (rtLen < sizeof(Dot11RadioTap) || rtLen > in_capturedLen) return 0;

    size_t dot11End = rtHdr->hasFCS_dataEnd(in_capturedLen);
    if (dot11End < rtLen + sizeof(Dot11) + sizeof(Beacon)) return 0;
    size_t dot11Len = dot11End - rtLen;

    if (in_BufSize < sizeof(Dot11RadioTap) + dot11Len) return 0;

    *reinterpret_cast<Dot11RadioTap*>(out_Buf) = Dot11RadioTap{};
    std::memcpy(out_Buf + sizeof(Dot11RadioTap), in_captured + rtLen, dot11Len);

    if (in_useUnicast) {
        reinterpret_cast<Dot11*>(out_Buf + sizeof(Dot11RadioTap))->setDst(in_staMac);
    }

    size_t new_frame_end = sizeof(Dot11RadioTap) + dot11Len;

    Beacon::CsaTag csa;
    new_frame_end = append_tag(out_Buf, in_BufSize, new_frame_end,
                               reinterpret_cast<const uint8_t*>(&csa), sizeof(csa));
    if (new_frame_end == 0) return 0;

    Beacon::EcsaTag ecsa;
    new_frame_end = append_tag(out_Buf, in_BufSize, new_frame_end,
                               reinterpret_cast<const uint8_t*>(&ecsa), sizeof(ecsa));
    if (new_frame_end == 0) return 0;

    return new_frame_end;
}
