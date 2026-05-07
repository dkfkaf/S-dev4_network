#include "radiohdr.h"
#include <cstdio>
#include <string>
#include <vector>

int main() {
    const std::vector<std::string> files = {
        "beacon-a2000ua-testap.pcap",
        "beacon-a2000ua-testap5g.pcap",
        "beacon-awus051nh-testap.pcap",
        "beacon-awus051nh-testap5g.pcap",
        "beacon-daiso-mywifi.pcap",
        "beacon-forcerecon-testap.pcap",
        "beacon-forcerecon-testap5g.pcap",
        "beacon-galaxy7-testap.pcap",
        "beacon-galaxy7-testap5g.pcap",
        "beacon-nexus5-testap.pcap",
        "beacon-nexus5-testap5g.pcap",
        "dot11-sample.pcap"
    };

    int pass = 0, fail = 0;

    printf("%-42s  %10s  %5s\n", "파일", "Power(dBm)", "FCS");
    printf("------------------------------------------------------------\n");

    for (const std::string& fname : files) {
        RadioHdr hdr;
        if (!hdr.loadPcap(fname)) {
            printf("%-42s  [LOAD FAILED]\n", fname.c_str());
            fail++;
            continue;
        }
        int8_t power = hdr.getPower(0);
        bool   fcs   = hdr.hasFCS(0);
        printf("%-42s  %10d  %5s\n", fname.c_str(), (int)power, fcs ? "YES" : "NO");
        pass++;
    }

    printf("------------------------------------------------------------\n");
    printf("총 %d개 파일  성공: %d  실패: %d\n", pass + fail, pass, fail);
    return fail > 0 ? 1 : 0;
}
