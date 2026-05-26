/* main.cpp — wips-parser 진입점.
   CLI 파싱 → pcap/detector/hopper 조립 → capture 스레드 launch → SIGINT 대기 → shutdown 순서로 실행.
   시그널 처리(g_signal_pipe self-pipe 패턴) + 프로세스 wiring 전담. 도메인 로직은 각 모듈에 위임. */

#include "pch.h"
#include "capture.h"
#include "channel_hopper.h"
#include "deauth_detector.h"
#include "i_detector.h"
#include "startup.h"
#include <fcntl.h>
#include <cerrno>
#include <memory>
#include <thread>
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

struct AdapterSetup {
    const char*      ifname;
    const char*      label;
    ChannelHopConfig config;
};

// pcap_t를 unique_ptr로 감싸 자동 close — 모든 exit 경로에서 누수 방지.
using PcapPtr = std::unique_ptr<pcap_t, decltype(&pcap_close)>;

int main(int argc, char* argv[]) {
    // 파이프/redirect(`| tee`, `> log`)에서도 stdout을 line-buffered로 유지.
    // 기본은 파이프 시 block-buffered(4KB) — frame 출력이 모였다가 burst로 dump됨.
    std::setvbuf(stdout, nullptr, _IOLBF, 0);

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
        if (std::strcmp(a, "--help") == 0 || std::strcmp(a, "-h") == 0) {
            print_usage();
            return 0;                                  // --help는 정상 종료
        } else if (std::strcmp(a, "--band") == 0 && i + 1 < argc) {
            const char* v = argv[++i];
            if      (std::strcmp(v, "2g")  == 0) band = BandOpt::twoFour;
            else if (std::strcmp(v, "5g")  == 0) band = BandOpt::five;
            else if (std::strcmp(v, "all") == 0) band = BandOpt::all;
            else {
                std::cerr << "[init] 알 수 없는 --band 값: " << v << "\n";
                print_usage();
                return 1;
            }
        } else if (std::strcmp(a, "--channels") == 0 && i + 1 < argc) {
            if (!parse_channel_list(argv[++i], customChannels)) {
                LOG(ERROR) << "[init] --channels 파싱 실패: " << argv[i];
                return 1;
            }
        } else if (a[0] == '-') {
            std::cerr << "[init] 알 수 없는 옵션: " << a << "\n";
            print_usage();
            return 1;
        } else {
            positional.push_back(a);
        }
    }

    run_startup_diagnostics();

    std::vector<AdapterSetup> adapters;
    auto pickConfig = [&]() -> ChannelHopConfig {
        if (!customChannels.empty()) {
            ChannelHopConfig c;
            c.channels = customChannels;
            c.dwell    = std::chrono::milliseconds(100);
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
        adapters.push_back({positional[0], nullptr, pickConfig()});
    } else if (positional.size() == 2) {
        if (std::strcmp(positional[0], positional[1]) == 0) {
            LOG(ERROR) << "[init] fast-iface와 dfs-iface는 달라야 합니다: " << positional[0];
            return 1;
        }
        adapters.push_back({positional[0], "fast", ChannelHopConfig::fastNonDfs()});
        adapters.push_back({positional[1], "dfs",  ChannelHopConfig::dfsOnly()});
    } else {
        print_usage();
        return 1;
    }

    for (const auto& a : adapters) {
        LOG(INFO) << "[init] 어댑터: " << a.ifname
                  << " | 채널 목록: " << a.config.channels.size() << "개";
    }

    // pcap 핸들을 RAII로 관리 — return 1 또는 main 종료 시 vector destructor가 자동 pcap_close.
    std::vector<PcapPtr> pcaps;
    for (const auto& a : adapters) {
        PcapPtr p(open_monitor(a.ifname), &pcap_close);
        if (!p) return 1;  // 이미 열린 pcaps는 vector 소멸 시 정리됨
        pcaps.push_back(std::move(p));
    }

    // detector를 typed local로 먼저 받아 policySummary 추출 후 IDetector vector로 이동.
    // 새 디텍터(EvilTwin 등) 추가도 동일 패턴 — concrete 타입에 접근 후 move.
    auto deauthDet = std::make_unique<DeauthFloodDetector>();
    const std::string deauthPolicy = deauthDet->policySummary();

    std::vector<std::unique_ptr<IDetector>> detectors;
    detectors.push_back(std::move(deauthDet));

    std::vector<std::unique_ptr<ChannelHopper>> hoppers;
    for (const auto& a : adapters) {
        hoppers.push_back(std::make_unique<ChannelHopper>(a.ifname, a.config));
        if (!hoppers.back()->start()) {
            LOG(ERROR) << "[init] channel hopper 시작 실패 (iface=" << a.ifname << ") — 종료";
            return 1;  // hoppers/pcaps RAII로 정리됨
        }
    }

    std::cout << "[*] mode          : "
              << (adapters.size() == 1 ? "single-adapter" : "dual-adapter") << "\n";
    for (size_t i = 0; i < adapters.size(); ++i) {
        std::cout << "[*] ";
        if (adapters[i].label) std::cout << adapters[i].label << "-iface : ";
        else                   std::cout << "interface     : ";
        std::cout << adapters[i].ifname << " — " << hoppers[i]->summary() << "\n";
    }
    std::cout << "[*] deauth policy : " << deauthPolicy << "\n"
              << "[*]                 정상 disconnect(reason 3/8)는 perSrcMac/perBssid에서 제외\n"
              << "[*] 802.11 management frame 캡처 시작 ... (Ctrl+C to stop)\n";

    std::signal(SIGINT,  on_sigint);
    std::signal(SIGTERM, on_sigint);
    std::signal(SIGPIPE, SIG_IGN);

    std::vector<std::thread> threads;
    threads.reserve(adapters.size());
    for (size_t i = 0; i < adapters.size(); ++i) {
        threads.emplace_back([&, i] {
            capture_loop(pcaps[i].get(), adapters[i].label, detectors, g_running);
        });
    }

    wait_for_shutdown_signal();
    LOG(INFO) << "[shutdown] 신호 수신 — 종료 시작";

    // 순서 중요: pcap_breakloop는 non-blocking signal — capture 스레드를 먼저 깨워서 join한다.
    // hopper.stop()은 iw hang 시 무한 대기 가능 — 그 위험을 capture 종료 경로와 분리하기 위해 뒤에 둔다.
    for (auto& p : pcaps) pcap_breakloop(p.get());

    for (auto& t : threads) t.join();
    LOG(INFO) << "[shutdown] capture 스레드 종료 완료";

    for (auto& h : hoppers) h->stop();
    LOG(INFO) << "[shutdown] hopper 정지 완료";

    pcaps.clear();  // 명시적 해제 — destructor가 pcap_close 호출
    LOG(INFO) << "[shutdown] pcap 핸들 해제 완료";

    ::close(g_signal_pipe[0]);
    ::close(g_signal_pipe[1]);
    return 0;
}
