#include "pch.h"
#include "capture.h"
#include "mgmt_parser.h"
#include "console_log.h"
#include <chrono>
#include <string>

pcap_t* open_monitor(const char* ifname) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_create(ifname, errbuf);
    if (!pcap) {
        LOG(ERROR) << "[pcap] pcap_create(" << ifname << ") 실패: " << errbuf
                   << " — root 권한과 monitor mode 인터페이스를 확인하세요.";
        return nullptr;
    }

    auto check = [&](int rc, const char* op) {
        if (rc != 0) {
            LOG(WARNING) << "[pcap] " << op << "(" << ifname << ") rc=" << rc;
        }
    };
    check(pcap_set_snaplen(pcap, 65535),               "set_snaplen");
    check(pcap_set_promisc(pcap, 1),                   "set_promisc");
    check(pcap_set_timeout(pcap, 100),                 "set_timeout");
    check(pcap_set_immediate_mode(pcap, 1),            "set_immediate_mode");
    check(pcap_set_buffer_size(pcap, 4 * 1024 * 1024), "set_buffer_size");

    if (int rc = pcap_activate(pcap); rc != 0) {
        LOG(ERROR) << "[pcap] activate(" << ifname << ") 실패 (rc=" << rc
                   << "): " << pcap_geterr(pcap);
        pcap_close(pcap);
        return nullptr;
    }
    LOG(INFO) << "[pcap] immediate mode 활성화 완료: " << ifname;

    int dlt = pcap_datalink(pcap);
    if (dlt != DLT_IEEE802_11_RADIO) {
        LOG(ERROR) << "[pcap] interface '" << ifname
                   << "' 는 monitor mode (radiotap) 가 아닙니다. DLT=" << dlt;
        pcap_close(pcap);
        return nullptr;
    }

    bpf_program fp;
    const char* filter = "type mgt and subtype deauth";
    if (pcap_compile(pcap, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_setfilter(pcap, &fp);
        pcap_freecode(&fp);
        LOG(INFO) << "[pcap] BPF 필터 적용: " << filter;
    } else {
        LOG(ERROR) << "[pcap] BPF 컴파일 실패: " << pcap_geterr(pcap);
    }
    return pcap;
}

void capture_loop(pcap_t* pcap, const char* label,
                  std::vector<std::unique_ptr<IDetector>>& detectors,
                  const std::atomic<bool>& running) {
    auto lastStats = std::chrono::steady_clock::now();

    while (running.load()) {
        pcap_pkthdr*   hdr = nullptr;
        const uint8_t* pkt = nullptr;
        int rc = pcap_next_ex(pcap, &hdr, &pkt);

        if (rc == 0)                continue;
        if (rc == PCAP_ERROR_BREAK) break;
        if (rc < 0) {
            LOG(ERROR) << "[pcap] pcap_next_ex"
                       << (label ? std::string("(") + label + ")" : std::string())
                       << " : " << pcap_geterr(pcap);
            break;
        }

        auto frame = parse_mgmt_frame(pkt, hdr->caplen);
        if (frame.has_value()) {
            const ParsedFrame& f = frame.value();
            print_frame(label, f);

            // 한 frame당 ts를 한 번 산정해 모든 디텍터에 broadcast — 시간선 일관성.
            // 디텍터는 자신이 관심 있는 frameType만 처리하고 나머지는 빈 vector를 반환한다.
            const auto ts = std::chrono::steady_clock::now();
            for (auto& d : detectors) {
                for (const auto& a : d->observe(ts, f)) {
                    LOG(ERROR) << "[alert] " << format_alert(a);
                    print_alert(a);
                }
            }
        }

        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(now - lastStats).count() >= 5) {
            pcap_stat ps;
            if (pcap_stats(pcap, &ps) == 0) {
                LOG(INFO) << "[stats]"
                          << (label ? std::string("(") + label + ")" : std::string())
                          << " received=" << ps.ps_recv
                          << " dropped_kernel=" << ps.ps_drop
                          << " dropped_iface="  << ps.ps_ifdrop;
                if (ps.ps_drop > 0) {
                    LOG(WARNING) << "[stats] kernel drop 발생 — BPF 필터/버퍼 확인 필요";
                }
            }
            lastStats = now;
        }
    }
}
