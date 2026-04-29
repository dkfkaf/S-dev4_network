#include "parser.h"

std::string mac_to_str(const uint8_t* mac) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buf);
}

bool parse_radiotap_len(const uint8_t* pkt, int caplen, int& rt_len_out)
{
    if (caplen < (int)sizeof(RadiotapHeader)) return false;
    const RadiotapHeader* rt = (const RadiotapHeader*)pkt;
    if (rt->version != 0) return false;
    int rt_len = rt->len;
    if (rt_len <= 0 || rt_len > caplen) return false;
    rt_len_out = rt_len;
    return true;
}

bool parse_pwr(const uint8_t* pkt, int caplen, int8_t& signal_out)
{
    if (caplen < (int)sizeof(RadiotapHeader)) return false;
    const RadiotapHeader* rt = (const RadiotapHeader*)pkt;
    if (rt->version != 0) return false;

    uint32_t present = rt->present;

    if (!(present & (1u << 5))) return false;

    const uint8_t* end = pkt + rt->len;

    const uint8_t* p = pkt + sizeof(RadiotapHeader);
    while (present & (1u << 31)) {
        if (p + 4 > end) return false;
        present = *(const uint32_t*)p;
        p += 4;
    }

    auto align_to = [&](uintptr_t n) {
        uintptr_t addr    = (uintptr_t)p;
        uintptr_t aligned = (addr + n - 1) & ~(n - 1);
        p += aligned - addr;
    };

    present = rt->present;

    if (present & (1u << 0)) { align_to(8); p += 8; }
    if (present & (1u << 1)) {              p += 1; }
    if (present & (1u << 2)) {              p += 1; }
    if (present & (1u << 3)) { align_to(2); p += 4; }
    if (present & (1u << 4)) {              p += 2; }

    if (p >= end) return false;
    signal_out = *(const int8_t*)p;
    return true;
}

void parse_essid(const uint8_t* p, int len, APInfo& ap) {
    int i = 0;
    while (i + 2 <= len) {
        uint8_t tag_num = p[i];
        uint8_t tag_len = p[i + 1];
        if (i + 2 + tag_len > len) break;
        const uint8_t* v = p + i + 2;

        if (tag_num == 0) {
            std::string s((const char*)v, tag_len);
            for (auto& c : s) if (c < 0x20 || c > 0x7E) c = '.';
            ap.essid = s;
            return;
        }
        i += 2 + tag_len;
    }
}

void packet_handler(u_char*, const struct pcap_pkthdr* h, const u_char* pkt)
{
    int caplen = h->caplen;
    int rt_len = 0;

    if (!parse_radiotap_len(pkt, caplen, rt_len)) return;
    if (rt_len >= caplen) return;

    const uint8_t* dot11 = pkt + rt_len;
    int dot11_len = caplen - rt_len;
    if (dot11_len < (int)sizeof(Dot11Header)) return;

    const Dot11Header* hdr = (const Dot11Header*)dot11;

    uint8_t type    = fc_type(hdr->frame_ctrl);
    uint8_t subtype = fc_subtype(hdr->frame_ctrl);

    if (type == 0 && subtype == 8) {
        const uint8_t* body     = dot11 + sizeof(Dot11Header);
        int            body_len = dot11_len - sizeof(Dot11Header);
        if (body_len < (int)sizeof(BeaconFixed)) return;

        const uint8_t* tagged     = body + sizeof(BeaconFixed);
        int            tagged_len = body_len - sizeof(BeaconFixed);
        std::string bssid = mac_to_str(hdr->addr3);

        int8_t pwr = 0;
        parse_pwr(pkt, caplen, pwr);

        std::lock_guard<std::mutex> lk(g_mtx);
        APInfo& ap = g_aps[bssid];
        ap.bssid = bssid;
        ap.beacons++;
        ap.pwr = pwr;
        parse_essid(tagged, tagged_len, ap);
        return;
    }

    if (type == 0 && subtype == 4) {
        std::string sta = mac_to_str(hdr->addr2);

        std::lock_guard<std::mutex> lk(g_mtx);
        StaInfo& s  = g_stas[sta];
        s.station   = sta;
        s.bssid     = "(not associated)";
        s.packets++;
        return;
    }

    if (type == 2) {
        uint8_t tods   = fc_tods(hdr->frame_ctrl);
        uint8_t fromds = fc_fromds(hdr->frame_ctrl);

        std::string sta, bssid;

        if (tods == 1 && fromds == 0) {
            sta   = mac_to_str(hdr->addr2);
            bssid = mac_to_str(hdr->addr1);
        } else if (tods == 0 && fromds == 1) {
            sta   = mac_to_str(hdr->addr1);
            bssid = mac_to_str(hdr->addr2);
        } else {
            return;
        }

        std::lock_guard<std::mutex> lk(g_mtx);
        StaInfo& s = g_stas[sta];
        s.station  = sta;
        s.bssid    = bssid;
        s.packets++;
        return;
    }
}
