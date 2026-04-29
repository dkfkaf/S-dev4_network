#include "pch.h"
#include "structs.h"
#include "parser.h"

std::map<std::string, APInfo>  g_aps;
std::map<std::string, StaInfo> g_stas;
std::mutex                     g_mtx;
std::atomic<bool>              g_running(true);
pcap_t*                        g_pcap = nullptr;

void sig_handler(int) {
    g_running.store(false);
    if (g_pcap)
        pcap_breakloop(g_pcap);
}

static void print_loop() {
    while (g_running.load()) {
        {
            std::lock_guard<std::mutex> lk(g_mtx);
            printf("\033[H\033[J");
            printf(" S-dev airodump\n\n");
            printf(" %-17s  %4s  %8s  %s\n",
                   "BSSID", "PWR", "Beacons", "ESSID");
            printf(" -------------------------------------------------\n");
            for (auto& kv : g_aps) {
                const APInfo& a = kv.second;
                if (a.pwr != 0)
                    printf(" %-17s  %4d  %8d  %s\n",
                           a.bssid.c_str(), (int)a.pwr, a.beacons, a.essid.c_str());
                else
                    printf(" %-17s  %4s  %8d  %s\n",
                           a.bssid.c_str(), "--", a.beacons, a.essid.c_str());
            }

            printf("\n");
            printf(" %-17s  %-17s  %8s\n", "Station MAC", "BSSID", "Packets");
            printf(" -------------------------------------------------\n");
            for (auto& kv : g_stas) {
                const StaInfo& s = kv.second;
                printf(" %-17s  %-17s  %8d\n",
                       s.station.c_str(), s.bssid.c_str(), s.packets);
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
}


int main(int argc, char* argv[]) {

    if (argc != 2) {
        fprintf(stderr, "syntax : airodump <interface>\n");
        fprintf(stderr, "sample : airodump mon0\n");
        return EXIT_FAILURE;
    }

    signal(SIGINT, sig_handler);

    const char* dev = argv[1];

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!pcap) {
        fprintf(stderr, "pcap_open_live(%s) failed: %s\n", dev, errbuf);
        return 1;
    }
    g_pcap = pcap;

    if (pcap_datalink(pcap) != 127) {
        fprintf(stderr, "[!] %s is not in monitor(radiotap) mode.\n", dev);
        fprintf(stderr, "    sudo airmon-ng start <iface>\n");
        pcap_close(pcap);
        return 1;
    }

    std::thread t_print(print_loop);

    pcap_loop(pcap, 0, packet_handler, nullptr);

    g_running.store(false);
    t_print.join();
    pcap_close(pcap);
    return 0;
}
