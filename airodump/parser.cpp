#include "parser.h"


/*mac 주소 파싱하는 함수*/

std::string mac_to_str(const uint8_t* mac) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buf);
}

// Radiotap 헤더 길이만 추출
/*캡처된 패킷 전체의 시작 포인터, 실제로 캡처된 바이트 수, 결과를 돌려받기 위한 부분*/
bool parse_radiotap_len(const uint8_t* pkt, int caplen, int& rt_len_out)
{
    if (caplen < (int)sizeof(RadiotapHeader)) return false; //캡처된 길이가 radiotap 헤더길이보다 짧으면 거부
    const RadiotapHeader* rt = (const RadiotapHeader*)pkt; // pkt를 RadiotapHeader 구조체 포인터로 캐스팅
    if (rt->version != 0) return false; // header revision 0을 기준으로 작성, revision이 바뀌면 코드 동작 안함
    int rt_len = rt->len; // radiotap 헤더의 전체 길이 저장

    /*radiotap 헤더는 최소한 자기 자신은 있어야 하기 때문에,
    또한 헤더 길이가 캡처된 전체 패킷보다 크면 비정상임*/
    if (rt_len <= 0 || rt_len > caplen) return false;
    rt_len_out = rt_len; //유효한 radiotap 길이 저장
    return true;
}

// Radiotap 가변 필드에서 신호 세기(Antenna Signal, bit5) 추출
//
// Radiotap 가변 필드 구조 (present 비트 순서대로):
// bit0: TSFT          (8byte, align8)
// bit1: Flags         (1byte)
// bit2: Rate          (1byte)
// bit3: Channel       (4byte, align2)
// bit4: FHSS          (2byte)
// bit5: AntennaSignal (1byte) ← 여기가 PWR!
//
// 각 필드를 순서대로 건너뛰면서 bit5 위치를 찾아야 함
bool parse_pwr(const uint8_t* pkt, int caplen, int8_t& signal_out)
{
    if (caplen < (int)sizeof(RadiotapHeader)) return false;
    const RadiotapHeader* rt = (const RadiotapHeader*)pkt;
    if (rt->version != 0) return false;

    uint32_t present = rt->present;

    // Antenna Signal(bit5)이 없으면 바로 포기
    if (!(present & (1u << 5))) return false;

    const uint8_t* end = pkt + rt->len;

    // 고정 헤더(8byte) 이후부터 가변 필드 시작
    // EXT(bit31)가 켜져 있으면 present 워드가 추가로 붙어있으므로 건너뜀
    const uint8_t* p = pkt + sizeof(RadiotapHeader);
    while (present & (1u << 31)) {
        if (p + 4 > end) return false;
        present = *(const uint32_t*)p; // 다음 present 워드
        p += 4;
    }

    // 정렬 헬퍼: p를 n의 배수 위치로 올림
    // 예) p=9, n=2 → p=10
    auto align_to = [&](uintptr_t n) {
        uintptr_t addr    = (uintptr_t)p;
        uintptr_t aligned = (addr + n - 1) & ~(n - 1);
        p += aligned - addr;
    };

    // present의 첫 번째 워드(헤더의 rt->present)로 필드 파싱
    present = rt->present;

    if (present & (1u << 0)) { align_to(8); p += 8; }  // TSFT
    if (present & (1u << 1)) {              p += 1; }  // Flags
    if (present & (1u << 2)) {              p += 1; }  // Rate
    if (present & (1u << 3)) { align_to(2); p += 4; }  // Channel (freq + flags)
    if (present & (1u << 4)) {              p += 2; }  // FHSS

    // bit5: Antenna Signal → 여기가 PWR!
    if (p >= end) return false;
    signal_out = *(const int8_t*)p;
    return true;
}

// Beacon Tagged Parameters에서 ESSID 추출
// p = 태그 파라미터 시작 포인터, len = 데이터 길이, ap = AP정보 구조체 참조
void parse_essid(const uint8_t* p, int len, APInfo& ap) {
    int i = 0;
    while (i + 2 <= len) {
        uint8_t tag_num = p[i];  //tag_num이 0이 나오면 그때 부터 essid 영역이라서
        uint8_t tag_len = p[i + 1];
        if (i + 2 + tag_len > len) break;
        const uint8_t* v = p + i + 2; //p+i==tag_num, p+i+1==tag_len, p+i+2==tag data

        if (tag_num == 0) {   // SSID 태그
            std::string s((const char*)v, tag_len);
            for (auto& c : s) if (c < 0x20 || c > 0x7E) c = '.'; //essid가 표현할 수 없는 문자일때, .으로 치환하는 코드
            ap.essid = s;
            return;   // SSID만 찾으면 됨
        }
        i += 2 + tag_len;
    }
}


    // 패킷 전체 구조
    // ┌─────────────────┬──────────────────┬─────────────────┬──────────────────────────┐
    // │  Radiotap 헤더  │  Dot11Header     │  BeaconFixed    │  Tagged Parameters       │
    // │  (rt_len 바이트)│  (24바이트)      │  (12바이트)     │  (SSID, 속도 등)         │
    // └─────────────────┴──────────────────┴─────────────────┴──────────────────────────┘
    // ↑                  ↑                  ↑                  ↑
    // pkt                dot11              body               tagged


// pcap 콜백
void packet_handler(u_char*, const struct pcap_pkthdr* h, const u_char* pkt)
{
    int caplen = h->caplen;
    int rt_len = 0;

    if (!parse_radiotap_len(pkt, caplen, rt_len)) return;
    if (rt_len >= caplen) return; //radiotap 헤더 뒤에 파싱할 802.11 데이터가 남아있는지 체크하는 코드

    const uint8_t* dot11 = pkt + rt_len; //캡처된 패킷 시작부분부터 radiotap 헤더까지 더해서, 802 위치 포인터 주기
    int dot11_len = caplen - rt_len;     //전체길이에서 radiotap 헤더 길이만 뺌
    if (dot11_len < (int)sizeof(Dot11Header)) return;

    const Dot11Header* hdr = (const Dot11Header*)dot11;

    uint8_t type    = fc_type(hdr->frame_ctrl);
    uint8_t subtype = fc_subtype(hdr->frame_ctrl); /*비콘 있는지 알려주는 타입*/

    // ── Beacon (type=0, subtype=8) ──────────────────────────────
    if (type == 0 && subtype == 8) {
        const uint8_t* body     = dot11 + sizeof(Dot11Header);
        int            body_len = dot11_len - sizeof(Dot11Header);
        if (body_len < (int)sizeof(BeaconFixed)) return;

        const uint8_t* tagged     = body + sizeof(BeaconFixed);
        int            tagged_len = body_len - sizeof(BeaconFixed);
        std::string bssid = mac_to_str(hdr->addr3);

        // PWR은 Radiotap 헤더에서 꺼냄 (802.11 바깥)
        int8_t pwr = 0;
        parse_pwr(pkt, caplen, pwr);

        std::lock_guard<std::mutex> lk(g_mtx);
        APInfo& ap = g_aps[bssid]; //bssid 기반으로 ap를 찾고, parse_essid를 사용해서 essid를 찾아냄
        ap.bssid = bssid;
        ap.beacons++;
        ap.pwr = pwr;
        parse_essid(tagged, tagged_len, ap);
        return;
    }

    // ── Probe Request (type=0, subtype=4) ───────────────────────
    // 클라이언트가 "주변에 AP 있어?" 하고 뿌리는 프레임
    // AP와 연결되지 않은 상태 → BSSID는 "(not associated)"
    if (type == 0 && subtype == 4) {
        std::string sta = mac_to_str(hdr->addr2); // 송신자 = 클라이언트 MAC

        std::lock_guard<std::mutex> lk(g_mtx);
        StaInfo& s  = g_stas[sta];
        s.station   = sta;
        s.bssid     = "(not associated)";
        s.packets++;
        return;
    }

    // ── Data Frame (type=2) ─────────────────────────────────────
    // 실제 인터넷 데이터가 오가는 프레임
    // ToDS/FromDS 비트로 방향을 판단해서 Station MAC과 BSSID를 구분함
    if (type == 2) {
        uint8_t tods   = fc_tods(hdr->frame_ctrl);
        uint8_t fromds = fc_fromds(hdr->frame_ctrl);

        std::string sta, bssid;

        if (tods == 1 && fromds == 0) {
            // 클라이언트 → AP 방향
            // addr1 = BSSID(수신지), addr2 = Station(송신지)
            sta   = mac_to_str(hdr->addr2);
            bssid = mac_to_str(hdr->addr1);
        } else if (tods == 0 && fromds == 1) {
            // AP → 클라이언트 방향
            // addr1 = Station(수신지), addr2 = BSSID(송신지)
            sta   = mac_to_str(hdr->addr1);
            bssid = mac_to_str(hdr->addr2);
        } else {
            return; // WDS(AP끼리 통신) 또는 IBSS(애드혹)는 무시
        }

        std::lock_guard<std::mutex> lk(g_mtx);
        StaInfo& s = g_stas[sta];
        s.station  = sta;
        s.bssid    = bssid;
        s.packets++;
        return;
    }
}
