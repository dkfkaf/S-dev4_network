/* main.cpp — wips-parser 진입점.
   CLI 파싱 → pcap/detector/hopper 조립 → capture 스레드 launch → SIGINT 대기 → shutdown.
   도메인 로직(CLI/어댑터 셋업/배너)은 startup.cpp에, 외부 명령은 subprocess.cpp에 위임. */

#include "pch.h"
#include "capture.h"
#include "channel_hopper.h"
#include "deauth_detector.h"
#include "i_detector.h"
#include "startup.h"
#include <fcntl.h>
#include <cerrno>
#include <thread>

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

// pcap_t를 unique_ptr로 감싸 자동 close — 모든 exit 경로에서 누수 방지.
using PcapPtr = std::unique_ptr<pcap_t, decltype(&pcap_close)>;

int main(int argc, char* argv[]) {
    // 파이프/redirect(`| tee`, `> log`)에서도 stdout을 line-buffered로 유지.
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

    const CliOpts opts = parse_cli(argc, argv);
    if (opts.showHelpAndExit) return 0;
    if (!opts.parseOk)        return 1;

    run_startup_diagnostics();

    const auto adapters = build_adapters(opts);
    if (adapters.empty()) return 1;

    // pcap 핸들을 RAII로 관리 — return 1 또는 main 종료 시 vector destructor가 자동 pcap_close.
    std::vector<PcapPtr> pcaps;
    for (const auto& a : adapters) {
        PcapPtr p(open_monitor(a.ifname.c_str()), &pcap_close);
        if (!p) return 1;
        pcaps.push_back(std::move(p));
    }

    auto deauthDet = std::make_unique<DeauthFloodDetector>();
    const std::vector<std::string> deauthPolicyLines = deauthDet->policyLines();
    std::vector<std::unique_ptr<IDetector>> detectors;
    detectors.push_back(std::move(deauthDet));

    std::vector<std::unique_ptr<ChannelHopper>> hoppers;
    for (const auto& a : adapters) {
        hoppers.push_back(std::make_unique<ChannelHopper>(a.ifname, a.config));
        if (!hoppers.back()->start()) {
            LOG(ERROR) << "[init] channel hopper 시작 실패 (iface=" << a.ifname << ") — 종료";
            return 1;
        }
    }

    print_banner(adapters, hoppers, deauthPolicyLines);

    std::signal(SIGINT,  on_sigint);
    std::signal(SIGTERM, on_sigint);
    std::signal(SIGPIPE, SIG_IGN);

    std::vector<std::thread> threads;
    threads.reserve(adapters.size());
    for (size_t i = 0; i < adapters.size(); ++i) {
        threads.emplace_back([&, i] {
            const char* label = adapters[i].label.empty() ? nullptr : adapters[i].label.c_str();
            capture_loop(pcaps[i].get(), label, detectors, g_running);
        });
    }

    wait_for_shutdown_signal();
    LOG(INFO) << "[shutdown] 신호 수신 — 종료 시작";

    // 순서 중요: pcap_breakloop는 non-blocking — capture 스레드를 먼저 깨워서 join한다.
    // hopper.stop()은 iw hang 시 무한 대기 가능 — 그 위험을 capture 종료 경로와 분리하기 위해 뒤에 둔다.
    for (auto& p : pcaps) pcap_breakloop(p.get());

    for (auto& t : threads) t.join();
    LOG(INFO) << "[shutdown] capture 스레드 종료 완료";

    for (auto& h : hoppers) h->stop();
    LOG(INFO) << "[shutdown] hopper 정지 완료";

    pcaps.clear();
    LOG(INFO) << "[shutdown] pcap 핸들 해제 완료";

    ::close(g_signal_pipe[0]);
    ::close(g_signal_pipe[1]);
    return 0;
}
