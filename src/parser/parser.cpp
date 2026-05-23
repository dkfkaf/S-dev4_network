#include "pch.h"
#include "mgmt_parser.h"
#include "dot11.h"

static std::optional<int8_t> extract_rssi(uint32_t present,
                                          const uint8_t* pktBuf, size_t radiotapLen) {
    if (!(present & Dot11RadioTap::PRESENT_DBM_SIGNAL)) return std::nullopt;

    size_t cursor = 0;
    if (!skipExtPresents(pktBuf, radiotapLen, present, cursor)) return std::nullopt;
    if (!advanceToField(present, radiotapLen,
                        Dot11RadioTap::PRESENT_DBM_SIGNAL, cursor)) return std::nullopt;

    if (cursor >= radiotapLen) return std::nullopt;
    return static_cast<int8_t>(pktBuf[cursor]);
}

// radiotap의 PRESENT_CHANNEL 필드(주파수 2바이트 + flags 2바이트)에서 채널 번호 추출.
// 2.4GHz: ch = (freq - 2407) / 5  (channel 14는 2484 special case)
// 5GHz:  ch = (freq - 5000) / 5
static std::optional<int> extract_channel(uint32_t present,
                                          const uint8_t* pktBuf, size_t radiotapLen) {
    if (!(present & Dot11RadioTap::PRESENT_CHANNEL)) return std::nullopt;

    size_t cursor = 0;
    if (!skipExtPresents(pktBuf, radiotapLen, present, cursor)) return std::nullopt;
    if (!advanceToField(present, radiotapLen,
                        Dot11RadioTap::PRESENT_CHANNEL, cursor)) return std::nullopt;

    cursor = alignTo(cursor, 2);  // CHANNEL 필드는 2-byte align
    if (cursor + 2 > radiotapLen) return std::nullopt;

    uint16_t freq = 0;
    std::memcpy(&freq, pktBuf + cursor, sizeof(freq));

    if (freq == 2484)                       return 14;
    if (freq >= 2412 && freq <= 2472)       return static_cast<int>((freq - 2407) / 5);
    if (freq >= 5170 && freq <= 5825)       return static_cast<int>((freq - 5000) / 5);
    return std::nullopt;
}

static std::optional<std::string> extract_ssid(const uint8_t* tags, size_t tagsLen) {
    const uint8_t* end = tags + tagsLen;
    const Dot11Tag* tag = (const Dot11Tag*)tags;

    while (tag->isValid(end)) {
        if (tag->num == 0)
            return std::string(tag->value(), tag->value() + tag->len);
        tag = tag->next();
    }
    return std::nullopt;
}

std::optional<ParsedFrame> parse_mgmt_frame(const uint8_t* data, size_t len) {
    if (len < sizeof(Dot11RadioTap) + sizeof(Dot11)) return std::nullopt;

    Dot11RadioTap rt;
    std::memcpy(&rt, data, sizeof(rt));

    size_t rtLen = rt.len();
    if (rtLen < sizeof(Dot11RadioTap) || rtLen > len) return std::nullopt;

    size_t frameEnd = rt.hasFCS_dataEnd(data, len);
    if (frameEnd < rtLen + sizeof(Dot11)) return std::nullopt;

    Dot11 dot11;
    std::memcpy(&dot11, data + rtLen, sizeof(Dot11));

    if (dot11.type() != DOT11_TYPE_MGMT) return std::nullopt;
    const uint8_t  frameSubtype = dot11.subtype();
    const size_t   bodyStart    = rtLen + sizeof(Dot11);

    ParsedFrame result{};
    size_t fixedLen = 0;

    // subtype별: fixed body 크기 결정 + 해당 type 고유 필드 추출 colocate
    switch (frameSubtype) {
        case MGMT_SUBTYPE_BEACON:
        case MGMT_SUBTYPE_PROBE_RESP: fixedLen = sizeof(Beacon);    break;
        case MGMT_SUBTYPE_PROBE_REQ:  fixedLen = 0;                 break;
        case MGMT_SUBTYPE_AUTH:       fixedLen = sizeof(Auth);      break;
        case MGMT_SUBTYPE_ASSOC_REQ:  fixedLen = sizeof(AssocReq);  break;
        case MGMT_SUBTYPE_ASSOC_RESP: fixedLen = sizeof(AssocResp); break;
        case MGMT_SUBTYPE_DEAUTH: {
            fixedLen = sizeof(Deauth);
            if (bodyStart + sizeof(Deauth) <= frameEnd) {
                Deauth d;
                std::memcpy(&d, data + bodyStart, sizeof(Deauth));
                result.reasonCode = d.reasonCode;
            }
            break;
        }
        default: return std::nullopt;
    }

    result.frameType = static_cast<Dot11MgmtSubtype>(frameSubtype);
    result.dst       = dot11.addr1;
    result.src       = dot11.addr2;
    result.bssid     = dot11.addr3;
    result.rssi      = extract_rssi(rt.it_present, data, rtLen);
    result.channel   = extract_channel(rt.it_present, data, rtLen);

    const size_t tagsStart = bodyStart + fixedLen;
    if (tagsStart < frameEnd)
        result.ssid = extract_ssid(data + tagsStart, frameEnd - tagsStart);

    return result;
}
