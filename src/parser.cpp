#include "pch.h"
#include "mgmt_parser.h"
#include "dot11.h"

static std::optional<int8_t> extract_rssi(uint32_t present,
                                          const uint8_t* pktBuf, size_t radiotapLen) {
    if (!(present & Dot11RadioTap::PRESENT_DBM_SIGNAL)) return std::nullopt;

    size_t cursor;
    if (!skipExtPresents(pktBuf, radiotapLen, present, cursor)) return std::nullopt;
    if (!advanceToField(present, radiotapLen,
                        Dot11RadioTap::PRESENT_DBM_SIGNAL, cursor)) return std::nullopt;

    if (cursor + 1 > radiotapLen) return std::nullopt;
    return static_cast<int8_t>(pktBuf[cursor]);
}

static std::optional<std::string> extract_ssid(const uint8_t* tags, size_t tagsLen) {
    for (size_t i = 0; i + 2 <= tagsLen; ) {
        uint8_t num  = tags[i];
        uint8_t len  = tags[i + 1];
        size_t  next = i + 2 + len;
        if (next > tagsLen) break;

        if (num == 0)
            return std::string(tags + i + 2, tags + i + 2 + len);
        i = next;
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

    const uint8_t* dot11Ptr = data + rtLen;
    Dot11 dot11;
    std::memcpy(&dot11, dot11Ptr, sizeof(Dot11));

    if (dot11.type() != DOT11_TYPE_MGMT) return std::nullopt;
    uint8_t frameSubtype = dot11.subtype();

    ParsedFrame result;
    switch (frameSubtype) {
        case MGMT_SUBTYPE_BEACON:     result.frameType = "Beacon";    break;
        case MGMT_SUBTYPE_PROBE_REQ:  result.frameType = "ProbeReq";  break;
        case MGMT_SUBTYPE_PROBE_RESP: result.frameType = "ProbeResp"; break;
        case MGMT_SUBTYPE_DEAUTH:     result.frameType = "Deauth";    break;
        case MGMT_SUBTYPE_AUTH:       result.frameType = "Auth";      break;
        case MGMT_SUBTYPE_ASSOC_REQ:  result.frameType = "AssocReq";  break;
        case MGMT_SUBTYPE_ASSOC_RESP: result.frameType = "AssocResp"; break;
        default: return std::nullopt;
    }

    result.dst   = dot11.addr1;
    result.src   = dot11.addr2;
    result.bssid = dot11.addr3;
    result.rssi  = extract_rssi(rt.it_present, data, rtLen);

    size_t fixedLen = 0;
    switch (frameSubtype) {
        case MGMT_SUBTYPE_BEACON:
        case MGMT_SUBTYPE_PROBE_RESP: fixedLen = sizeof(Beacon);    break;
        case MGMT_SUBTYPE_PROBE_REQ:  fixedLen = 0;                 break;
        case MGMT_SUBTYPE_DEAUTH:     fixedLen = sizeof(Deauth);    break;
        case MGMT_SUBTYPE_AUTH:       fixedLen = sizeof(Auth);      break;
        case MGMT_SUBTYPE_ASSOC_REQ:  fixedLen = sizeof(AssocReq);  break;
        case MGMT_SUBTYPE_ASSOC_RESP: fixedLen = sizeof(AssocResp); break;
        default: return std::nullopt;
    }

    size_t tagsStart = rtLen + sizeof(Dot11) + fixedLen;
    if (tagsStart < frameEnd)
        result.ssid = extract_ssid(data + tagsStart, frameEnd - tagsStart);

    return result;
}
