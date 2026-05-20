#include "pch.h"
#include "mgmt_parser.h"

static std::atomic<bool> g_running(true);
static void on_sigint(int) { g_running.store(false); }

static void usage() {
    std::cout
        << "syntax : wips-parser <interface>\n"
        << "sample : wips-parser mon0\n";
}

static void print_frame(const ParsedFrame& f) {
    std::cout
        << "[" << f.frameType << "]"
        << "  src="   << f.src.toString()
        << "  dst="   << f.dst.toString()
        << "  bssid=" << f.bssid.toString();
    if (f.ssid.has_value()) {
        if (f.ssid.value().empty()) std::cout << "  ssid=<hidden>";
        else                        std::cout << "  ssid=\"" << f.ssid.value() << "\"";
    }
    if (f.rssi.has_value())
        std::cout << "  rssi=" << static_cast<int>(f.rssi.value()) << "dBm";
    std::cout << "\n";
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return 1;
    }

    const char* ifname = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* pcap = pcap_open_live(ifname, 65535, 1, 1, errbuf);
    if (!pcap) {
        std::cerr << "pcap_open_live : " << errbuf << "\n"
                  << "  -> root 권한과 monitor mode 인터페이스를 확인하세요.\n";
        return 1;
    }

    int dlt = pcap_datalink(pcap);
    if (dlt != DLT_IEEE802_11_RADIO) {
        std::cerr << "interface '" << ifname
                  << "' 는 monitor mode (radiotap) 가 아닙니다. "
                  << "current DLT = " << dlt << "\n";
        pcap_close(pcap);
        return 1;
    }

    // 관리 프레임만 캡처
    bpf_program fp;
    if (pcap_compile(pcap, &fp, "type mgt", 1, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_setfilter(pcap, &fp);
        pcap_freecode(&fp);
    }

    std::signal(SIGINT,  on_sigint);
    std::signal(SIGTERM, on_sigint);

    std::cout << "[*] interface : " << ifname << "\n"
              << "[*] 802.11 management frame 캡처 시작 ... (Ctrl+C to stop)\n";

    while (g_running.load()) {
        pcap_pkthdr*   hdr = nullptr;
        const uint8_t* pkt = nullptr;
        int rc = pcap_next_ex(pcap, &hdr, &pkt);

        if (rc == 0)                continue;
        if (rc == PCAP_ERROR_BREAK) break;
        if (rc < 0) {
            std::cerr << "pcap_next_ex : " << pcap_geterr(pcap) << "\n";
            break;
        }

        auto frame = parse_mgmt_frame(pkt, hdr->caplen);
        if (frame.has_value()) {
            print_frame(frame.value());
        }
    }

    std::cout << "\n[*] stopping ...\n";
    pcap_close(pcap);
    return 0;
}
