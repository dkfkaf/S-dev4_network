#include "parser.h"

std::string mac_to_str(const uint8_t* mac) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buf);
}

// Radiotap 헤더 길이만 추출
bool parse_radiotap_len(const uint8_t* pkt, int caplen, int& rt_len_out)
{
    if (caplen < (int)sizeof(RadiotapHeader)) return false; //캡처된 길이가 radiotap 헤더길이보다 짧으면 거부
    const RadiotapHeader* rt = (const RadiotapHeader*)pkt; // pkt를 RadiotapHeader 구조체 포인터로 캐스팅
    if (rt->version != 0) return false; // radiotap 버전이 0이 아니면 유효하지 않으므로 false 반환... 왜?

    int rt_len = rt->len; // radiotap 헤더의 전체 길이 저장
    if (rt_len <= 0 || rt_len > caplen) return false; // radiotap 헤더 길이가 0 이하거나 캡처된 길이보다 크면 false
    rt_len_out = rt_len; //유효한 radiotap 길이 저장
    return true;
}

// Beacon Tagged Parameters에서 ESSID 추출
// p = 태그 파라미터 시작 포인터, len = 데이터 길이, ap = AP정보 구조체 참조 <- 애 이해가 안감
void parse_essid(const uint8_t* p, int len, APInfo& ap) {
    int i = 0;
    while (i + 2 <= len) {
        uint8_t tag_num = p[i];
        uint8_t tag_len = p[i + 1];
        if (i + 2 + tag_len > len) break;
        const uint8_t* v = p + i + 2;

        if (tag_num == 0) {   // SSID 태그
            std::string s((const char*)v, tag_len);
            for (auto& c : s) if (c < 0x20 || c > 0x7E) c = '.';
            ap.essid = s;
            return;   // SSID만 찾으면 됨
        }
        i += 2 + tag_len;
    }
}

// pcap 콜백
void packet_handler(u_char*, const struct pcap_pkthdr* h, const u_char* pkt)
{
    // 패킷 전체 구조
    // ┌─────────────────┬──────────────────┬─────────────────┬──────────────────────────┐
    // │  Radiotap 헤더  │  Dot11Header     │  BeaconFixed    │  Tagged Parameters       │
    // │  (rt_len 바이트)│  (24바이트)      │  (8바이트)      │  (SSID, 속도 등)         │
    // └─────────────────┴──────────────────┴─────────────────┴──────────────────────────┘
    // ↑                  ↑                  ↑                  ↑
    // pkt                dot11              body               tagged

    int caplen = h->caplen;

    int rt_len = 0;
    if (!parse_radiotap_len(pkt, caplen, rt_len)) return;
    if (rt_len >= caplen) return;

    // ┌─────────────────┬─────────────────────────────────────────────────────────────┐
    // │  Radiotap 헤더  │                    나머지 (dot11_len)                        │
    // │←   rt_len      →│←                    dot11_len                              →│
    // └─────────────────┴─────────────────────────────────────────────────────────────┘
    const uint8_t* dot11 = pkt + rt_len;
    int dot11_len = caplen - rt_len;
    if (dot11_len < (int)sizeof(Dot11Header)) return;

    const Dot11Header* hdr = (const Dot11Header*)dot11;

    // frame_ctrl 비트 구조
    // ┌──────────────────┬────────────┬───────────────────────────┐
    // │  subtype (4비트) │ type(2비트)│  기타 플래그              │
    // │  8 = Beacon      │ 0 = 관리   │  To DS, From DS 등        │
    // └──────────────────┴────────────┴───────────────────────────┘
    uint8_t type    = fc_type(hdr->frame_ctrl);
    uint8_t subtype = fc_subtype(hdr->frame_ctrl);

    if (type == 0 && subtype == 8) {

        // ┌──────────────────┬─────────────────┬──────────────────────────┐
        // │  Dot11Header     │  BeaconFixed     │  Tagged Parameters       │
        // │←  sizeof(Dot11) →│← sizeof(Beacon) →│←      tagged_len        →│
        // │                  ↑                  ↑                           │
        // │                 body              tagged                        │
        // └──────────────────┴─────────────────┴──────────────────────────┘
        const uint8_t* body   = dot11 + sizeof(Dot11Header);
        int            body_len = dot11_len - sizeof(Dot11Header);
        if (body_len < (int)sizeof(BeaconFixed)) return;

        const uint8_t* tagged     = body + sizeof(BeaconFixed);
        int            tagged_len = body_len - sizeof(BeaconFixed);

        // Dot11Header 구조
        // ┌──────────┬──────────┬──────────┬──────────┬──────────┐
        // │frame_ctrl│ duration │  addr1   │  addr2   │  addr3   │
        // │ (2바이트)│ (2바이트)│ (6바이트)│ (6바이트)│ (6바이트)│
        // │          │          │  수신지  │  송신지  │  BSSID   │
        // └──────────┴──────────┴──────────┴──────────┴──────────┘
        std::string bssid = mac_to_str(hdr->addr3);

        std::lock_guard<std::mutex> lk(g_mtx);
        APInfo& ap = g_aps[bssid];
        ap.bssid = bssid;
        ap.beacons++;
        parse_essid(tagged, tagged_len, ap);
    }
}