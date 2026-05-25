#include "pch.h"
#include "mgmt_parser.h"
#include "deauth_detector.h"
#include "channel_hopper.h"
#include "console_log.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <cerrno>
#include <algorithm>
#include <memory>
#include <mutex>
#include <thread>
#include <unordered_set>
#include <vector>

static std::atomic<bool> g_running(true);
static int               g_signal_pipe[2] = {-1, -1};

static void on_sigint(int) {
    g_running.store(false);
    const char x = 1;
    ssize_t n = ::write(g_signal_pipe[1], &x, 1);
    (void)n;
}

static void wait_for_shutdown_signal() {
    char buf;
    for (;;) {
        ssize_t n = ::read(g_signal_pipe[0], &buf, 1);
        if (n > 0) return;
        if (n == 0) return;
        if (errno != EINTR) return;
    }
}

static void usage() {
    std::cout
        << "syntax : wips-parser [--band 2g|5g|all] [--channels c1,c2,...] <iface> [<dfs-iface>]\n"
        << "  single-adapter : wips-parser mon0\n"
        << "                   2.4GHz + 5GHz non-DFS 모든 채널 순환 (500ms dwell)\n"
        << "  2.4GHz only    : wips-parser --band 2g mon0\n"
        << "  5GHz only      : wips-parser --band 5g mon0\n"
        << "  custom         : wips-parser --channels 1,6,11 mon0\n"
        << "  dual-adapter   : wips-parser mon0 mon1\n"
        << "                   <iface>     : 2.4GHz + 5GHz non-DFS 빠른 sweep (200ms)\n"
        << "                   <dfs-iface> : 5GHz DFS 전담 (2000ms dwell)\n";
}

static DeauthEvent make_deauth_event(const ParsedFrame& f) {
    return {std::chrono::steady_clock::now(),
            f.src, f.reasonCode, f.channel};
}

static pcap_t* open_monitor(const char* ifname) {
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
    const char* filter = "type mgt and (subtype deauth or subtype disassoc)";
    if (pcap_compile(pcap, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_setfilter(pcap, &fp);
        pcap_freecode(&fp);
        LOG(INFO) << "[pcap] BPF 필터 적용: " << filter;
    } else {
        LOG(ERROR) << "[pcap] BPF 컴파일 실패: " << pcap_geterr(pcap);
    }
    return pcap;
}

static void capture_loop(pcap_t* pcap, const char* label, DeauthFloodDetector& detector) {
    auto lastStats = std::chrono::steady_clock::now();

    while (g_running.load()) {
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

            if (f.frameType == MGMT_SUBTYPE_DEAUTH) {
                LOG(WARNING) << "[detect] Deauth 수신 | src=" << f.src.toString()
                             << " dst=" << f.dst.toString()
                             << (f.channel.has_value()
                                    ? " channel=" + std::to_string(f.channel.value())
                                    : "");
                for (const auto& a : detector.observe(make_deauth_event(f))) {
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

struct AdapterSetup {
    const char*      ifname;
    const char*      label;
    ChannelHopConfig cfg;
};

static const std::vector<int>& valid_channel_set() {
    static const std::vector<int> kValid = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
        36, 40, 44, 48,
        52, 56, 60, 64,
        100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
        149, 153, 157, 161, 165,
    };
    return kValid;
}

static bool parse_channel_list(const char* csv, std::vector<int>& out) {
    out.clear();
    const auto& valid = valid_channel_set();
    std::unordered_set<int> seen;
    const char* p = csv;
    while (*p) {
        char* end = nullptr;
        long v = std::strtol(p, &end, 10);
        if (end == p) return false;
        const int ch = static_cast<int>(v);
        if (std::find(valid.begin(), valid.end(), ch) == valid.end()) {
            LOG(ERROR) << "[init] 알 수 없는 802.11 채널: " << ch;
            return false;
        }
        if (!seen.insert(ch).second) {
            LOG(ERROR) << "[init] 중복된 채널: " << ch;
            return false;
        }
        out.push_back(ch);
        p = end;
        while (*p == ',' || *p == ' ' || *p == '\t') ++p;
    }
    return !out.empty();
}

static bool exec_silent(const char* prog,
                        std::initializer_list<const char*> args) {
    pid_t pid = ::fork();
    if (pid < 0) return false;
    if (pid == 0) {
        int devnull = ::open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            ::dup2(devnull, STDOUT_FILENO);
            ::dup2(devnull, STDERR_FILENO);
            ::close(devnull);
        }
        std::vector<const char*> argv;
        argv.reserve(args.size() + 2);
        argv.push_back(prog);
        for (const char* a : args) argv.push_back(a);
        argv.push_back(nullptr);
        ::execvp(prog, const_cast<char* const*>(argv.data()));
        ::_exit(127);
    }
    int status = 0;
    while (::waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) return false;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static void run_startup_diagnostics() {
    if (::geteuid() != 0) {
        LOG(FATAL) << "[init] root 권한 없음 — sudo로 실행 필요";
    }
    if (!exec_silent("iw", {"--version"})) {
        LOG(FATAL) << "[init] iw 미설치 — sudo apt install iw 후 재시도";
    }
    LOG(INFO) << "[init] 사전 진단 통과 (root + iw 확인)";
}

static void init_log_dir() {
    const char* path = "/var/log/wips";
    if (::mkdir(path, 0755) == 0 || errno == EEXIST) {
        FLAGS_log_dir = path;
    } else {
        std::cerr << "[init] " << path << " 사용 불가 ("
                  << std::generic_category().message(errno)
                  << ") — stderr 전용 로깅\n";
    }
}

int main(int argc, char* argv[]) {
    init_log_dir();
    google::InitGoogleLogging(argv[0]);
    FLAGS_logtostderr = true;
    FLAGS_v           = 1;

    if (::pipe(g_signal_pipe) != 0) {
        LOG(FATAL) << "[init] signal pipe 생성 실패: "
                   << std::generic_category().message(errno);
    }
    int wflags = ::fcntl(g_signal_pipe[1], F_GETFL, 0);
    if (wflags >= 0) ::fcntl(g_signal_pipe[1], F_SETFL, wflags | O_NONBLOCK);

    enum class BandOpt { all, twoFour, five };
    BandOpt          band = BandOpt::all;
    std::vector<int> customChannels;
    std::vector<const char*> positional;

    for (int i = 1; i < argc; ++i) {
        const char* a = argv[i];
        if (std::strcmp(a, "--band") == 0 && i + 1 < argc) {
            const char* v = argv[++i];
            if      (std::strcmp(v, "2g")  == 0) band = BandOpt::twoFour;
            else if (std::strcmp(v, "5g")  == 0) band = BandOpt::five;
            else if (std::strcmp(v, "all") == 0) band = BandOpt::all;
            else { usage(); return 1; }
        } else if (std::strcmp(a, "--channels") == 0 && i + 1 < argc) {
            if (!parse_channel_list(argv[++i], customChannels)) {
                LOG(ERROR) << "[init] --channels 파싱 실패: " << argv[i];
                return 1;
            }
        } else if (a[0] == '-') {
            usage();
            return 1;
        } else {
            positional.push_back(a);
        }
    }

    run_startup_diagnostics();

    std::vector<AdapterSetup> adapters;
    auto pickCfg = [&]() -> ChannelHopConfig {
        if (!customChannels.empty()) {
            ChannelHopConfig c;
            c.channels = customChannels;
            c.dwell    = std::chrono::milliseconds(500);
            return c;
        }
        switch (band) {
            case BandOpt::twoFour: return ChannelHopConfig::twoFourOnly();
            case BandOpt::five:    return ChannelHopConfig::fastNonDfs();
            case BandOpt::all:
            default:               return ChannelHopConfig{};
        }
    };

    if (positional.size() == 1) {
        adapters.push_back({positional[0], nullptr, pickCfg()});
    } else if (positional.size() == 2) {
        if (std::strcmp(positional[0], positional[1]) == 0) {
            LOG(ERROR) << "[init] fast-iface와 dfs-iface는 달라야 합니다: " << positional[0];
            return 1;
        }
        adapters.push_back({positional[0], "fast", ChannelHopConfig::fastNonDfs()});
        adapters.push_back({positional[1], "dfs",  ChannelHopConfig::dfsOnly()});
    } else {
        usage();
        return 1;
    }

    for (const auto& a : adapters) {
        LOG(INFO) << "[init] 어댑터: " << a.ifname
                  << " | 채널 목록: " << a.cfg.channels.size() << "개";
    }

    std::vector<pcap_t*> pcaps;
    for (const auto& a : adapters) {
        pcap_t* p = open_monitor(a.ifname);
        if (!p) {
            for (auto* x : pcaps) pcap_close(x);
            return 1;
        }
        pcaps.push_back(p);
    }

    DeauthFloodDetector detector;
    std::vector<std::unique_ptr<ChannelHopper>> hoppers;
    for (const auto& a : adapters) {
        hoppers.push_back(std::make_unique<ChannelHopper>(a.ifname, a.cfg));
        hoppers.back()->start();
    }

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

    std::signal(SIGINT,  on_sigint);
    std::signal(SIGTERM, on_sigint);
    std::signal(SIGPIPE, SIG_IGN);

    std::vector<std::thread> threads;
    threads.reserve(adapters.size());
    for (size_t i = 0; i < adapters.size(); ++i) {
        threads.emplace_back([&, i] {
            capture_loop(pcaps[i], adapters[i].label, detector);
        });
    }

    wait_for_shutdown_signal();
    LOG(INFO) << "[shutdown] 신호 수신 — 종료 시작";

    for (auto* p : pcaps)   pcap_breakloop(p);
    for (auto& h : hoppers) h->stop();
    LOG(INFO) << "[shutdown] hopper 정지 완료";

    for (auto& t : threads) t.join();
    LOG(INFO) << "[shutdown] capture 스레드 종료 완료";

    for (auto* p : pcaps) pcap_close(p);
    LOG(INFO) << "[shutdown] pcap 핸들 해제 완료";

    ::close(g_signal_pipe[0]);
    ::close(g_signal_pipe[1]);
    return 0;
}
