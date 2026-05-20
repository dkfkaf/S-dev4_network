#include "pch.h"
#include "mgmt_parser.h"
#include "dot11.h"

// Radiotap 헤더에서 DBM_SIGNAL(RSSI) 값을 추출한다.
// present: it_present 비트마스크,  pktBuf: 패킷 시작 포인터,  radiotapLen: radiotap 헤더 길이.
static std::optional<int8_t> extract_rssi(uint32_t present,
                                          const uint8_t* pktBuf, size_t radiotapLen) {
    if (!(present & Dot11RadioTap::PRESENT_DBM_SIGNAL)) return std::nullopt;

    size_t cursor;
    if (!skipExtPresents(pktBuf, radiotapLen, present, cursor)) return std::nullopt;
    if (!advanceToField(present, radiotapLen,
                        Dot11RadioTap::PRESENT_DBM_SIGNAL, cursor)) return std::nullopt;

    // bit 5 DBM_SIGNAL: 부호 있는 1바이트 (dBm)
    if (cursor + 1 > radiotapLen) return std::nullopt;
    return static_cast<int8_t>(pktBuf[cursor]);
}

// Tagged Parameters에서 SSID(태그 0)를 찾는다.
// 태그가 존재하면 ssid 문자열을 담은 optional 반환 (len=0이면 hidden SSID = 빈 문자열).
// 태그 자체가 없으면 nullopt 반환 — SSID 미포함 프레임과 hidden SSID를 구분할 수 있다.
//
// TLV 와이어 포맷: [num : 1B][len : 1B][data : len B] ... 반복
//   - i + 2 <= tagsLen : num·len 헤더 2바이트를 읽을 공간 확인
//   - next > tagsLen   : len 이 남은 버퍼 초과 → 손상 TLV 로 판단하고 안전 종료
static std::optional<std::string> extract_ssid(const uint8_t* tags, size_t tagsLen) {
    for (size_t i = 0; i + 2 <= tagsLen; ) {
        uint8_t num  = tags[i];
        uint8_t len  = tags[i + 1];
        size_t  next = i + 2 + len;
        if (next > tagsLen) break;       // 손상 TLV — 안전 종료

        if (num == 0)                    // SSID 태그 발견 (len=0 이면 hidden SSID)
            return std::string(tags + i + 2, tags + i + 2 + len);
        i = next;
    }
    return std::nullopt;
}

// 802.11 management frame 한 개를 파싱해 ParsedFrame을 반환한다.
// 비관리 프레임·지원하지 않는 서브타입·버퍼 부족 시 std::nullopt 반환.
//
// 모든 관리 프레임에서 주소 필드 역할은 서브타입과 무관하게 동일하다:
//   addr1 = 수신자(dst),  addr2 = 송신자(src),  addr3 = BSSID
std::optional<ParsedFrame> parse_mgmt_frame(const uint8_t* data, size_t len) {
    if (len < sizeof(Dot11RadioTap) + sizeof(Dot11)) return std::nullopt;

    Dot11RadioTap rt;
    std::memcpy(&rt, data, sizeof(rt));

    size_t rtLen = rt.len();
    if (rtLen < sizeof(Dot11RadioTap) || rtLen > len) return std::nullopt;

    // FCS가 있으면 끝 4바이트를 제외한 실제 프레임 끝 위치를 계산한다.
    size_t frameEnd = rt.hasFCS_dataEnd(data, len);
    if (frameEnd < rtLen + sizeof(Dot11)) return std::nullopt;

    const uint8_t* dot11Ptr = data + rtLen;
    Dot11 dot11;
    std::memcpy(&dot11, dot11Ptr, sizeof(Dot11));

    if (dot11.type() != DOT11_TYPE_MGMT) return std::nullopt;
    uint8_t frameSubtype = dot11.subtype();

    // 첫 번째 switch: 지원 서브타입인지 확인하고 frameType을 결정한다.
    // 알 수 없는 서브타입은 여기서 nullopt 반환해 이후 코드는 7가지 케이스만 고려하면 된다.
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

    result.dst   = dot11.addr1;     // addr1 = 수신자
    result.src   = dot11.addr2;     // addr2 = 송신자
    result.bssid = dot11.addr3;     // addr3 = BSSID (서브타입 불문 공통)
    result.rssi  = extract_rssi(rt.it_present, data, rtLen);

    // 두 번째 switch: 서브타입별 fixed params 크기를 구해 Tagged Parameters 시작 위치를 계산한다.
    // Dot11(24바이트) + fixed params 바로 다음부터 Tagged Parameters가 시작된다.
    //   Beacon/ProbeResp : 12 (timestamp 8 + beaconInterval 2 + capInfo 2)
    //   ProbeReq         :  0 (fixed params 없음)
    //   Deauth           :  2 (reasonCode)
    //   Auth             :  6 (authAlgo 2 + seqNum 2 + statusCode 2)
    //   AssocReq         :  4 (capInfo 2 + listenInterval 2)
    //   AssocResp        :  6 (capInfo 2 + statusCode 2 + AID 2)
    // default 가드: 첫 switch와 케이스가 어긋났을 때 조용히 잘못 동작하지 않게 한다.
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

    // Tagged Parameters 범위: [tagsStart, frameEnd)
    size_t tagsStart = rtLen + sizeof(Dot11) + fixedLen;
    if (tagsStart < frameEnd)
        result.ssid = extract_ssid(data + tagsStart, frameEnd - tagsStart);

    return result;
}
