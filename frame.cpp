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

static size_t find_csa_insert_pos(const uint8_t* tags,
                                  size_t tags_len,
                                  size_t& existingLen)
{
    existingLen = 0;

    size_t pos = 0;
    while (pos + 2 <= tags_len) {
        uint8_t tagNum = tags[pos];
        uint8_t tagLen = tags[pos + 1];
        size_t  total  = 2 + tagLen;

        if (pos + total > tags_len) break;

        if (tagNum == CSA_TAG_NUMBER) {
            existingLen = total;
            return pos;
        }
        if (tagNum > CSA_TAG_NUMBER) {
            return pos;
        }
        pos += total;
    }
    return tags_len;
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

    if (outBufSize < sizeof(dot11RadioTap) + dot11Len + sizeof(CsaTag)) return 0;

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

    size_t existingLen;
    size_t insertPos = tagsStart + find_csa_insert_pos(outBuf + tagsStart,
                                                       tagsEnd - tagsStart,
                                                       existingLen);

    if (existingLen > 0) {
        if (existingLen != sizeof(CsaTag)) {
            std::memmove(outBuf + insertPos + sizeof(CsaTag),
                         outBuf + insertPos + existingLen,
                         tagsEnd - (insertPos + existingLen));
            tagsEnd += static_cast<int>(sizeof(CsaTag)) - static_cast<int>(existingLen);
        }
    } else {
        std::memmove(outBuf + insertPos + sizeof(CsaTag),
                     outBuf + insertPos,
                     tagsEnd - insertPos);
        tagsEnd += sizeof(CsaTag);
    }

    CsaTag* csa      = reinterpret_cast<CsaTag*>(outBuf + insertPos);
    csa->tagNumber   = CSA_TAG_NUMBER;
    csa->tagLength   = CSA_TAG_LENGTH;
    csa->switchMode  = CSA_SWITCH_MODE;
    csa->newChannel  = CSA_NEW_CHANNEL;
    csa->switchCount = CSA_COUNT;

    return tagsEnd;
}
