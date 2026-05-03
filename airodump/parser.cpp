#include "parser.h"

// ── Mac class implementation ──────────────────────────────────────────────────

Mac::Mac(const char* s) {
    unsigned int v[6] = {};
    sscanf(s, "%x:%x:%x:%x:%x:%x", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]);
    for (int i = 0; i < 6; i++) mac_[i] = static_cast<uint8_t>(v[i]);
}

Mac::Mac(const std::string& s) : Mac(s.c_str()) {}

Mac::Mac(const Mac& r) {
    memcpy(mac_, r.mac_, 6);
}

std::string Mac::toString() const {
    char buf[18];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac_[0], mac_[1], mac_[2], mac_[3], mac_[4], mac_[5]);
    return std::string(buf);
}

Mac Mac::fromString(const std::string& s) {
    return Mac(s);
}

// ── Radiotap length ───────────────────────────────────────────────────────────

bool parse_radiotap_len(const uint8_t* pkt, int caplen, int& rt_len_out)
{
    if (caplen < static_cast<int>(sizeof(dot11RadioTap))) return false;
    const dot11RadioTap* rt = reinterpret_cast<const dot11RadioTap*>(pkt);
    if (rt->it_version != 0) return false;
    int rt_len = rt->it_len;
    if (rt_len <= 0 || rt_len > caplen) return false;
    rt_len_out = rt_len;
    return true;
}

// ── Antenna Signal (PWR) ──────────────────────────────────────────────────────

bool parse_pwr(const uint8_t* pkt, int caplen, int8_t& signal_out)
{
    if (caplen < static_cast<int>(sizeof(dot11RadioTap))) return false;
    const dot11RadioTap* rt = reinterpret_cast<const dot11RadioTap*>(pkt);
    if (rt->it_version != 0) return false;

    uint32_t present = rt->it_present;
    if (!(present & (1u << 5))) return false;   // bit5 = Antenna Signal

    const uint8_t* end = pkt + rt->it_len;

    // ext present words (bit31 = next present word exists)
    const uint8_t* p = pkt + sizeof(dot11RadioTap);
    while (present & (1u << 31)) {
        if (p + 4 > end) return false;
        present = *reinterpret_cast<const uint32_t*>(p);
        p += 4;
    }

    auto align_to = [&](uintptr_t n) {
        uintptr_t addr    = reinterpret_cast<uintptr_t>(p);
        uintptr_t aligned = (addr + n - 1) & ~(n - 1);
        p += aligned - addr;
    };

    present = rt->it_present;
    if (present & (1u << 0)) { align_to(8); p += 8; }   // TSFT    (8B)
    if (present & (1u << 1)) {              p += 1; }    // Flags   (1B)
    if (present & (1u << 2)) {              p += 1; }    // Rate    (1B)
    if (present & (1u << 3)) { align_to(2); p += 4; }   // Channel (4B)
    if (present & (1u << 4)) {              p += 2; }    // FHSS    (2B)
    // bit5 = Antenna Signal (1B) <- target

    if (p >= end) return false;
    signal_out = *reinterpret_cast<const int8_t*>(p);
    return true;
}

// ── ESSID Tagged Parameter ────────────────────────────────────────────────────

void parse_essid(const uint8_t* p, int len, APInfo& ap)
{
    const uint8_t* end = p + len;
    PTaggedParam tp = reinterpret_cast<PTaggedParam>(const_cast<uint8_t*>(p));

    while (reinterpret_cast<uint8_t*>(tp) + 2 <= end) {
        if (reinterpret_cast<uint8_t*>(tp) + 2 + tp->len > end) break;

        if (tp->tag == 0) {   // tag 0 = SSID
            std::string s(reinterpret_cast<const char*>(tp->data), tp->len);
            for (auto& c : s) if (c < 0x20 || c > 0x7E) c = '.';
            ap.essid = s;
            return;
        }
        // advance to next TaggedParam (+2 handled inside struct)
        tp = reinterpret_cast<PTaggedParam>(
            reinterpret_cast<uint8_t*>(tp) + 2 + tp->len
        );
    }
}

// ── Packet handler ────────────────────────────────────────────────────────────

void packet_handler(u_char*, const struct pcap_pkthdr* h, const u_char* pkt)
{
    int caplen = h->caplen;
    int rt_len = 0;

    if (!parse_radiotap_len(pkt, caplen, rt_len)) return;
    if (rt_len >= caplen) return;

    // dot11MacHdr: starts right after radiotap
    const dot11MacHdr* hdr =
        reinterpret_cast<const dot11MacHdr*>(pkt + rt_len);
    int dot11_len = caplen - rt_len;
    if (dot11_len < static_cast<int>(sizeof(dot11MacHdr))) return;

    uint8_t type    = fc_type(hdr->frameControl);
    uint8_t subtype = fc_subtype(hdr->frameControl);

    // Beacon (Management / Beacon)
    if (type == 0 && subtype == 8) {
        const uint8_t* body     = reinterpret_cast<const uint8_t*>(hdr) + sizeof(dot11MacHdr);
        int            body_len = dot11_len - static_cast<int>(sizeof(dot11MacHdr));
        if (body_len < static_cast<int>(sizeof(dot11Beacon))) return;

        const dot11Beacon* beacon = reinterpret_cast<const dot11Beacon*>(body);

        const uint8_t* tagged     = reinterpret_cast<const uint8_t*>(beacon) + sizeof(dot11Beacon);
        int            tagged_len = body_len - static_cast<int>(sizeof(dot11Beacon));

        // Beacon: addr3 = BSSID
        std::string bssid = hdr->addr3.toString();

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

    // Probe Request
    if (type == 0 && subtype == 4) {
        std::string sta = hdr->addr2.toString();

        std::lock_guard<std::mutex> lk(g_mtx);
        StaInfo& s  = g_stas[sta];
        s.station   = sta;
        s.bssid     = "(not associated)";
        s.packets++;
        return;
    }

    // Data frame
    if (type == 2) {
        uint8_t tods   = fc_tods(hdr->frameControl);
        uint8_t fromds = fc_fromds(hdr->frameControl);

        std::string sta, bssid;

        if (tods == 1 && fromds == 0) {
            // STA -> AP: addr2=STA, addr1=BSSID
            sta   = hdr->addr2.toString();
            bssid = hdr->addr1.toString();
        } else if (tods == 0 && fromds == 1) {
            // AP -> STA: addr1=STA, addr2=BSSID
            sta   = hdr->addr1.toString();
            bssid = hdr->addr2.toString();
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
