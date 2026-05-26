#include "pch.h"
#include "capture.h"
#include "mgmt_parser.h"
#include "console_log.h"

pcap_t* open_monitor(const char* ifname) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_create(ifname, errbuf);
    if (!pcap) {
        LOG(ERROR) << "[pcap] pcap_create(" << ifname << ") 실패: " << errbuf
                   << " — root 권한과 monitor mode 인터페이스를 확인하세요.";
        return nullptr;
    }

    // pcap_set_* 함수들은 activate 전 단순 setter — 실용상 실패 거의 없음.
    // 진짜 실패하는 경우(예: buffer size 비정상)는 다음 pcap_activate에서 잡힘.
    //
    // [timeout vs immediate_mode 관계]
    // immediate_mode=1이면 packet당 즉시 전달 — timeout 만료 trigger 자체가 안 됨.
    // 즉 timeout 100ms는 immediate_mode 미지원 드라이버에서만 활용되는 fallback safeguard.
    pcap_set_snaplen     (pcap, 65535);              // 전체 frame 캡처 (max snaplen)
    pcap_set_promisc     (pcap, 1);                  // promiscuous mode 활성
    pcap_set_timeout     (pcap, 100);                // ms — fallback (immediate_mode 우선)
    pcap_set_immediate_mode(pcap, 1);                // frame당 즉시 전달 (alert latency 최소화)
    pcap_set_buffer_size (pcap, 4 * 1024 * 1024);    // 4MB — burst 시 dropped_kernel 방지 마진

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

            // 한 frame당 timestamp를 한 번 산정해 모든 디텍터에 broadcast — 시간선 일관성.
            // 디텍터는 자신이 관심 있는 frameType만 처리하고 나머지는 빈 vector를 반환한다.
            const auto timestamp = std::chrono::steady_clock::now();
            for (auto& d : detectors) {
                for (const auto& a : d->observe(timestamp, f)) {
                    print_alert(a);   // stdout 단일 출력 — print_frame과 같은 스트림으로 시간 순 보임
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
