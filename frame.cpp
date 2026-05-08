#include "frame.h"
#include "dot11.h"
#include <cstring>

static bool radiotap_has_fcs(const uint8_t* rt, size_t rt_len) {
    if (rt_len < sizeof(dot11RadioTap)) return false;

    uint32_t firstPresent;
    std::memcpy(&firstPresent, rt + 4, 4);

    if (!(firstPresent & RT_PRESENT_FLAGS)) return false;

    size_t   cursor = 8;
    uint32_t p      = firstPresent;
    while (p & RT_PRESENT_EXT) {
        if (cursor + 4 > rt_len) return false;
        uint32_t next;
        std::memcpy(&next, rt + cursor, 4);
        cursor += 4;
        p = next;
    }

    if (firstPresent & RT_PRESENT_TSFT) {
        if (cursor % 8 != 0) cursor += (8 - cursor % 8);
        cursor += 8;
    }

    if (cursor >= rt_len) return false;

    return (rt[cursor] & RT_FLAG_FCS_AT_END) != 0;
}

static size_t insert_or_replace_tag(uint8_t* outBuf,
                                    size_t outBufSize,
                                    size_t tagsStart,
                                    size_t tagsEnd,
                                    uint8_t tagNumber,
                                    const uint8_t* tagBytes,
                                    size_t tagBytesLen)
{
    size_t existingLen = 0;
    size_t pos         = 0;
    size_t tagsLen     = tagsEnd - tagsStart;
    const uint8_t* tags = outBuf + tagsStart;

    while (pos + 2 <= tagsLen) {
        uint8_t tn = tags[pos];
        uint8_t tl = tags[pos + 1];
        size_t  total = 2 + tl;
        if (pos + total > tagsLen) break;
        if (tn == tagNumber) { existingLen = total; break; }
        if (tn > tagNumber)  break;
        pos += total;
    }
    size_t insertPos = tagsStart + pos;

    if (existingLen > 0) {
        if (existingLen != tagBytesLen) {
            size_t newTagsEnd = tagsEnd - existingLen + tagBytesLen;
            if (newTagsEnd > outBufSize) return 0;
            std::memmove(outBuf + insertPos + tagBytesLen,
                         outBuf + insertPos + existingLen,
                         tagsEnd - (insertPos + existingLen));
            tagsEnd = newTagsEnd;
        }
    } else {
        if (tagsEnd + tagBytesLen > outBufSize) return 0;
        std::memmove(outBuf + insertPos + tagBytesLen,
                     outBuf + insertPos,
                     tagsEnd - insertPos);
        tagsEnd += tagBytesLen;
    }

    std::memcpy(outBuf + insertPos, tagBytes, tagBytesLen);
    return tagsEnd;
}

size_t build_csa_beacon(uint8_t* outBuf, size_t outBufSize,
                        const uint8_t* captured, size_t capturedLen,
                        bool useUnicast, const Mac& staMac)
{
    if (capturedLen < sizeof(dot11RadioTap)) return 0;

    uint16_t rtLenRaw;
    std::memcpy(&rtLenRaw, captured + 2, 2);
    size_t rtLen = rtLenRaw;
    if (rtLen < sizeof(dot11RadioTap) || rtLen > capturedLen) return 0;

    size_t dot11End = capturedLen - (radiotap_has_fcs(captured, rtLen) ? 4 : 0);

    if (dot11End < rtLen + sizeof(dot11MacHdr) + BEACON_FIXED_PARAM_LEN) return 0;
    size_t dot11Len = dot11End - rtLen;

    if (outBufSize < sizeof(dot11RadioTap) + dot11Len) return 0;

    dot11RadioTap* rtOut = reinterpret_cast<dot11RadioTap*>(outBuf);
    rtOut->it_version = 0;
    rtOut->it_pad     = 0;
    rtOut->it_len     = sizeof(dot11RadioTap);
    rtOut->it_present = 0;

    std::memcpy(outBuf + sizeof(dot11RadioTap), captured + rtLen, dot11Len);

    if (useUnicast) {
        std::memcpy(outBuf + sizeof(dot11RadioTap) + offsetof(dot11MacHdr, addr1),
                    staMac.mac_, 6);
    }

    size_t tagsStart = sizeof(dot11RadioTap) + sizeof(dot11MacHdr) + BEACON_FIXED_PARAM_LEN;
    size_t tagsEnd   = sizeof(dot11RadioTap) + dot11Len;

    CsaTag csa;
    csa.tagNumber   = CSA_TAG_NUMBER;
    csa.tagLength   = CSA_TAG_LENGTH;
    csa.switchMode  = CHSW_SWITCH_MODE;
    csa.newChannel  = CHSW_NEW_CHANNEL;
    csa.switchCount = CHSW_SWITCH_COUNT;

    tagsEnd = insert_or_replace_tag(outBuf, outBufSize, tagsStart, tagsEnd,
                                    CSA_TAG_NUMBER,
                                    reinterpret_cast<const uint8_t*>(&csa),
                                    sizeof(csa));
    if (tagsEnd == 0) return 0;

    EcsaTag ecsa;
    ecsa.tagNumber   = ECSA_TAG_NUMBER;
    ecsa.tagLength   = ECSA_TAG_LENGTH;
    ecsa.switchMode  = CHSW_SWITCH_MODE;
    ecsa.newOpClass  = ECSA_NEW_OP_CLASS;
    ecsa.newChannel  = CHSW_NEW_CHANNEL;
    ecsa.switchCount = CHSW_SWITCH_COUNT;

    tagsEnd = insert_or_replace_tag(outBuf, outBufSize, tagsStart, tagsEnd,
                                    ECSA_TAG_NUMBER,
                                    reinterpret_cast<const uint8_t*>(&ecsa),
                                    sizeof(ecsa));
    if (tagsEnd == 0) return 0;

    return tagsEnd;
}
