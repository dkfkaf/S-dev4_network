#include "pch.h"
#include "mgmt_parser.h"
#include "deauth_detector.h"
#include "channel_hopper.h"
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

static std::atomic<bool> g_running(true);
static void on_sigint(int) { g_running.store(false); }

// 여러 capture thread가 std::cout/std::cerr에 동시 출력 시 라인 섞임 방지
static std::mutex g_outputMtx;

static void usage() {
    std::cout
        << "syntax : wips-parser <iface> [<dfs-iface>]\n"
        << "  single-adapter : wips-parser mon0\n"
        << "                   2.4GHz + 5GHz non-DFS 모든 채널 순환 (500ms dwell)\n"
        << "  dual-adapter   : wips-parser mon0 mon1\n"
        << "                   <iface>     : 2.4GHz + 5GHz non-DFS 빠른 sweep (200ms)\n"
        << "                   <dfs-iface> : 5GHz DFS 전담 (2000ms dwell)\n";
}

// label=nullptr이면 prefix 생략 (single-adapter 모드)
static void print_frame(const char* label, const ParsedFrame& f) {
    std::lock_guard<std::mutex> lock(g_outputMtx);
    if (label) std::cout << "[" << label << "]";
    std::cout
        << "[" << toString(f.frameType) << "]"
        << "  src="   << f.src.toString()
        << "  dst="   << f.dst.toString()
        << "  bssid=" << f.bssid.toString();
    if (f.ssid.has_value()) {
        if (f.ssid.value().empty()) std::cout << "  ssid=<hidden>";
        else                        std::cout << "  ssid=\"" << f.ssid.value() << "\"";
    }
    if (f.rssi.has_value())
        std::cout << "  rssi=" << static_cast<int>(f.rssi.value()) << "dBm";
    if (f.channel.has_value())
        std::cout << "  ch=" << f.channel.value();
    if (f.reasonCode.has_value())
        std::cout << "  reason=" << f.reasonCode.value();
    std::cout << "\n";
}

static void print_alert(const Alert& a) {
    std::lock_guard<std::mutex> lock(g_outputMtx);
    std::cout << "[ALERT " << toString(a.severity) << "] " << a.message << "\n";
}

// 인터페이스를 monitor mode pcap으로 열고, type=mgt BPF 필터를 설정해 반환한다.
// 실패 시 nullptr 반환 + stderr 진단.
static pcap_t* open_monitor(const char* ifname) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(ifname, 65535, 1, 1, errbuf);
    if (!pcap) {
        std::cerr << "pcap_open_live(" << ifname << ") : " << errbuf << "\n"
                  << "  -> root 권한과 monitor mode 인터페이스를 확인하세요.\n";
        return nullptr;
    }

    int dlt = pcap_datalink(pcap);
    if (dlt != DLT_IEEE802_11_RADIO) {
        std::cerr << "interface '" << ifname
                  << "' 는 monitor mode (radiotap) 가 아닙니다. DLT=" << dlt << "\n";
        pcap_close(pcap);
        return nullptr;
    }

    bpf_program fp;
    if (pcap_compile(pcap, &fp, "type mgt", 1, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_setfilter(pcap, &fp);
        pcap_freecode(&fp);
    }
    return pcap;
}

// 한 pcap에서 패킷을 받아 파싱 → 출력 → detector 전달. g_running이 false면 종료.
// label은 prefix용 (nullptr이면 생략).
static void capture_loop(pcap_t* pcap, const char* label, DeauthFloodDetector& detector) {
    while (g_running.load()) {
        pcap_pkthdr*   hdr = nullptr;
        const uint8_t* pkt = nullptr;
        int rc = pcap_next_ex(pcap, &hdr, &pkt);

        if (rc == 0)                continue;
        if (rc == PCAP_ERROR_BREAK) break;
        if (rc < 0) {
            std::lock_guard<std::mutex> lock(g_outputMtx);
            std::cerr << "pcap_next_ex";
            if (label) std::cerr << "(" << label << ")";
            std::cerr << " : " << pcap_geterr(pcap) << "\n";
            break;
        }

        auto frame = parse_mgmt_frame(pkt, hdr->caplen);
        if (!frame.has_value()) continue;

        const ParsedFrame& f = frame.value();
        print_frame(label, f);

        if (f.frameType == MGMT_SUBTYPE_DEAUTH) {
            // detector.observe()는 내부 mutex로 thread-safe
            for (const auto& a : detector.observe(DeauthEvent::from(f))) print_alert(a);
        }
    }
}

struct AdapterSetup {
    const char*      ifname;
    const char*      label;     // nullptr이면 single-adapter 모드 (prefix 없음)
    ChannelHopConfig cfg;
};

int main(int argc, char* argv[]) {
    // ① argv 파싱 → 어댑터 1개 또는 2개로 구성
    std::vector<AdapterSetup> adapters;
    if (argc == 2) {
        adapters.push_back({argv[1], nullptr, ChannelHopConfig{}});
    } else if (argc == 3) {
        if (std::strcmp(argv[1], argv[2]) == 0) {
            std::cerr << "fast-iface와 dfs-iface는 달라야 합니다: " << argv[1] << "\n";
            return 1;
        }
        adapters.push_back({argv[1], "fast", ChannelHopConfig::fastNonDfs()});
        adapters.push_back({argv[2], "dfs",  ChannelHopConfig::dfsOnly()});
    } else {
        usage();
        return 1;
    }

    // ② 모든 어댑터 pcap 오픈 — 하나라도 실패하면 cleanup 후 종료
    std::vector<pcap_t*> pcaps;
    for (const auto& a : adapters) {
        pcap_t* p = open_monitor(a.ifname);
        if (!p) {
            for (auto* x : pcaps) pcap_close(x);
            return 1;
        }
        pcaps.push_back(p);
    }

    std::signal(SIGINT,  on_sigint);
    std::signal(SIGTERM, on_sigint);

    // ③ detector + hopper 준비 (ChannelHopper는 mutex/thread를 가져 non-movable → unique_ptr)
    DeauthFloodDetector detector;
    std::vector<std::unique_ptr<ChannelHopper>> hoppers;
    for (const auto& a : adapters) {
        hoppers.push_back(std::make_unique<ChannelHopper>(a.ifname, a.cfg));
        hoppers.back()->start();
    }

    // ④ 배너
    std::cout << "[*] mode          : "
              << (adapters.size() == 1 ? "single-adapter" : "dual-adapter") << "\n";
    for (size_t i = 0; i < adapters.size(); ++i) {
        std::cout << "[*] ";
        if (adapters[i].label) std::cout << adapters[i].label << "-iface : ";
        else                   std::cout << "interface     : ";
        std::cout << adapters[i].ifname << " — " << hoppers[i]->summary() << "\n";
    }
    std::cout << "[*] deauth window : 10s (info=10/warn=20/critical=40 global,"
                                       " 5/10/20 per-source)\n"
              << "[*] 802.11 management frame 캡처 시작 ... (Ctrl+C to stop)\n";

    // ⑤ 어댑터별 capture thread 스폰. 공유 detector + 출력 mutex로 직렬화.
    std::vector<std::thread> threads;
    threads.reserve(adapters.size());
    for (size_t i = 0; i < adapters.size(); ++i) {
        threads.emplace_back([&, i] {
            capture_loop(pcaps[i], adapters[i].label, detector);
        });
    }

    for (auto& t : threads) t.join();

    // ⑥ cleanup
    std::cout << "\n[*] stopping ...\n";
    for (auto& h : hoppers) h->stop();
    for (auto* p : pcaps)   pcap_close(p);
    return 0;
}
