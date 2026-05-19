#include "pch.h"
#include "mgmt_parser.h"
#include "dot11.h"
#include "tag.h"

// Radiotap 헤더에서 DBM_SIGNAL(RSSI) 값을 추출한다.
//
// Radiotap 필드는 it_present 비트마스크의 비트 순서(0→31)대로 버퍼에 배치된다.
// 따라서 DBM_SIGNAL(bit 5)을 읽으려면 앞에 오는 필드들을 크기만큼 순서대로 건너뛰어야 한다.
//   bit 0 TSFT    : 8바이트, align 8
//   bit 1 FLAGS   : 1바이트
//   bit 2 RATE    : 1바이트
//   bit 3 CHANNEL : 4바이트, align 2
//   bit 4 FHSS    : 2바이트
//   bit 5 DBM_SIGNAL ← 여기
//
// 확장 present 워드(bit 31=EXT)가 있으면 필드 데이터는 모든 present 워드 다음에서
// 시작하므로, 필드를 읽기 전에 확장 워드를 전부 건너뛴다.
static bool extract_rssi(const uint8_t* rtBuf, size_t rtLen, int8_t& rssiOut) {
    if (rtLen < sizeof(Dot11RadioTap)) return false;

    Dot11RadioTap rt;
    std::memcpy(&rt, rtBuf, sizeof(rt));

    if (!(rt.it_present & Dot11RadioTap::PRESENT_DBM_SIGNAL)) return false;

    // 확장 present 워드를 모두 건너뛴다 — 필드 데이터는 그 뒤에서 시작
    size_t   cursor = sizeof(Dot11RadioTap);
    uint32_t p      = rt.it_present;
    while (p & Dot11RadioTap::PRESENT_EXT) {
        if (cursor + sizeof(uint32_t) > rtLen) return false;
        std::memcpy(&p, rtBuf + cursor, sizeof(p));
        cursor += sizeof(uint32_t);
    }

    // 첫 번째 present 워드(표준 네임스페이스)의 비트 순서대로 필드를 건너뛴다.
    // 확장 워드의 필드들은 표준 필드 뒤에 위치하므로 여기서는 고려하지 않는다.
    uint32_t present = rt.it_present;

    if (present & Dot11RadioTap::PRESENT_TSFT) {      // bit 0: 8바이트, align 8
        cursor  = Dot11RadioTap::alignTo(cursor, 8);
        cursor += sizeof(uint64_t);
    }
    if (cursor > rtLen) return false;

    if (present & Dot11RadioTap::PRESENT_FLAGS)   cursor += 1;  // bit 1: 1바이트
    if (cursor > rtLen) return false;

    if (present & Dot11RadioTap::PRESENT_RATE)    cursor += 1;  // bit 2: 1바이트
    if (cursor > rtLen) return false;

    if (present & Dot11RadioTap::PRESENT_CHANNEL) {             // bit 3: 4바이트, align 2
        cursor  = Dot11RadioTap::alignTo(cursor, 2);
        cursor += 4;
    }
    if (cursor > rtLen) return false;

    if (present & Dot11RadioTap::PRESENT_FHSS) cursor += 2;     // bit 4: 2바이트
    if (cursor >= rtLen) return false;

    rssiOut = static_cast<int8_t>(rtBuf[cursor]);  // bit 5: 부호 있는 1바이트 (dBm)
    return true;
}

// Tagged Parameters에서 SSID(태그 0)를 찾아 반환한다.
// 숨겨진 AP(hidden SSID)는 len=0이므로 빈 문자열이 반환될 수 있다.
static std::string extract_ssid(const uint8_t* tags, size_t tagsLen) {
    std::string ssid;
    scan_tags(tags, tagsLen, [&](TagView tv) -> bool {
        if (tv.num != 0) return true;   // 태그 0이 아니면 계속 탐색
        ssid = std::string(reinterpret_cast<const char*>(tv.data), tv.len);
        return false;  // 찾았으면 순회 중단
    });
    return ssid;
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

    // frameControl 하위 바이트 레이아웃: [version(0-1)][type(2-3)][subtype(4-7)]
    uint8_t lowByte      = static_cast<uint8_t>(dot11.frameControl & 0xFF);
    uint8_t frameType    = (lowByte >> 2) & 0x3;
    uint8_t frameSubtype = (lowByte >> 4) & 0xF;

    if (frameType != DOT11_TYPE_MGMT) return std::nullopt;

    // 첫 번째 switch: 지원 서브타입인지 확인하고 타입 이름을 결정한다.
    // 알 수 없는 서브타입은 여기서 nullopt 반환해 이후 코드는 7가지 케이스만 고려하면 된다.
    std::string typeName;
    switch (frameSubtype) {
        case MGMT_SUBTYPE_BEACON:     typeName = "Beacon";    break;
        case MGMT_SUBTYPE_PROBE_REQ:  typeName = "ProbeReq";  break;
        case MGMT_SUBTYPE_PROBE_RESP: typeName = "ProbeResp"; break;
        case MGMT_SUBTYPE_DEAUTH:     typeName = "Deauth";    break;
        case MGMT_SUBTYPE_AUTH:       typeName = "Auth";      break;
        case MGMT_SUBTYPE_ASSOC_REQ:  typeName = "AssocReq";  break;
        case MGMT_SUBTYPE_ASSOC_RESP: typeName = "AssocResp"; break;
        default: return std::nullopt;
    }

    ParsedFrame result;
    result.frameType = typeName;
    result.dst       = dot11.addr1;   // addr1 = 수신자
    result.src       = dot11.addr2;   // addr2 = 송신자
    result.bssid     = dot11.addr3;   // addr3 = BSSID (서브타입 불문 공통)
    result.hasRssi   = extract_rssi(data, rtLen, result.rssi);

    // 두 번째 switch: 서브타입별 fixed params 크기를 구해 Tagged Parameters 시작 위치를 계산한다.
    // Dot11(24바이트) + fixed params 바로 다음부터 Tagged Parameters가 시작된다.
    //   Beacon/ProbeResp : 12 (timestamp 8 + beaconInterval 2 + capInfo 2)
    //   ProbeReq         :  0 (fixed params 없음)
    //   Deauth           :  2 (reasonCode)
    //   Auth             :  6 (authAlgo 2 + seqNum 2 + statusCode 2)
    //   AssocReq         :  4 (capInfo 2 + listenInterval 2)
    //   AssocResp        :  6 (capInfo 2 + statusCode 2 + AID 2)
    size_t fixedLen = 0;
    switch (frameSubtype) {
        case MGMT_SUBTYPE_BEACON:
        case MGMT_SUBTYPE_PROBE_RESP: fixedLen = sizeof(Beacon);    break;
        case MGMT_SUBTYPE_PROBE_REQ:  fixedLen = 0;                 break;
        case MGMT_SUBTYPE_DEAUTH:     fixedLen = sizeof(Deauth);    break;
        case MGMT_SUBTYPE_AUTH:       fixedLen = sizeof(Auth);      break;
        case MGMT_SUBTYPE_ASSOC_REQ:  fixedLen = sizeof(AssocReq);  break;
        case MGMT_SUBTYPE_ASSOC_RESP: fixedLen = sizeof(AssocResp); break;
    }

    // Tagged Parameters 범위: [tagsStart, frameEnd)
    size_t tagsStart = rtLen + sizeof(Dot11) + fixedLen;
    if (tagsStart <= frameEnd)
        result.ssid = extract_ssid(data + tagsStart, frameEnd - tagsStart);

    return result;
}
