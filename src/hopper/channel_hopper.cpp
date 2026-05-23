#include "pch.h"
#include "channel_hopper.h"
#include <sys/wait.h>
#include <sstream>

ChannelHopConfig ChannelHopConfig::fastNonDfs() {
    return {
        {1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161},
        std::chrono::milliseconds(200),
    };
}

ChannelHopConfig ChannelHopConfig::dfsOnly() {
    return {
        // 120~128은 weather radar 채널이라 보통 제외. 116은 일부 국가에서만 가용
        {52, 56, 60, 64, 100, 104, 108, 112, 116, 132, 136, 140},
        std::chrono::milliseconds(2000),
    };
}

ChannelHopper::ChannelHopper(std::string iface, ChannelHopConfig cfg)
    : iface_(std::move(iface)), cfg_(std::move(cfg)) {}

ChannelHopper::~ChannelHopper() { stop(); }

void ChannelHopper::start() {
    if (cfg_.channels.empty()) {
        std::cerr << "[!] channel list가 비어있어 channel hopper를 시작하지 않습니다\n";
        return;
    }
    if (running_.exchange(true)) return;
    // 이전 worker가 연속 실패로 자가 종료했다면 thread는 여전히 joinable —
    // joinable한 thread에 새 thread를 대입하면 std::terminate 가 호출되므로 먼저 join.
    if (worker_.joinable()) worker_.join();
    worker_ = std::thread([this] { run(); });
}

void ChannelHopper::stop() {
    // worker가 자가 종료 (연속 실패로 running_=false 후 break) 했을 수도 있으므로
    // exchange 결과와 무관하게 joinable이면 항상 join. 안 그러면 ~thread() 가 joinable thread에서
    // std::terminate 를 호출함.
    running_.store(false);
    stopCv_.notify_all();  // dwell 대기 중인 worker를 즉시 깨움
    if (worker_.joinable()) worker_.join();
}

std::optional<int> ChannelHopper::currentChannel() const {
    int ch = currentChannel_.load();
    if (ch < 0) return std::nullopt;
    return ch;
}

// `iw dev <iface> set channel <n>` 을 fork/execlp로 호출한다.
// system()을 피해 shell injection을 방지. iw는 성공 시 silent이고 실패 시에만 stderr에
// 진단 메시지를 출력하므로 일부러 silencing하지 않는다 — 권한/인터페이스 문제 디버깅에 필요.
// snprintf는 locale-aware라서 async-signal-safe가 아님 — 반드시 fork 이전에 변환.

//iw dev <iface_> set channel <channel>
bool ChannelHopper::setChannel(int channel) {
    char chBuf[16];
    std::snprintf(chBuf, sizeof(chBuf), "%d", channel);

    pid_t pid = fork();
    if (pid < 0) return false;

    if (pid == 0) {
        ::execlp("iw", "iw", "dev", iface_.c_str(), "set", "channel", chBuf,
                 static_cast<char*>(nullptr));
        ::_exit(127);
    }

    int status = 0;
    if (::waitpid(pid, &status, 0) < 0) return false;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}


/*그냥 채널목록 사람이 보기 편하게 출력해주는 부분*/
std::string ChannelHopper::summary() const {
    // 2.4GHz (1~14)와 5GHz (36+) 채널을 분리해 출력
    std::vector<int> ch24, ch5;
    for (int ch : cfg_.channels) {
        (ch <= 14 ? ch24 : ch5).push_back(ch);
    }

    auto joinCsv = [](const std::vector<int>& v) {
        std::ostringstream s;
        for (size_t i = 0; i < v.size(); ++i) {
            if (i > 0) s << ",";
            s << v[i];
        }
        return s.str();
    };

    std::ostringstream oss;
    if (!ch24.empty())                       oss << "2.4GHz(" << joinCsv(ch24) << ")";
    if (!ch24.empty() && !ch5.empty())       oss << " + ";
    if (!ch5.empty())                        oss << "5GHz("   << joinCsv(ch5)  << ")";
    oss << " — " << cfg_.dwell.count() << "ms dwell";
    return oss.str();
}

void ChannelHopper::run() {
    constexpr int PER_CHANNEL_FAIL_LIMIT = 3;

    // 채널별 실패 추적: 같은 채널이 3회 실패하면 영구 skip.
    // 2.4GHz-only 어댑터에서 5GHz 채널 실패 시 호퍼 전체가 죽지 않고 동작 가능한 채널만 순회.
    std::vector<int>  failures(cfg_.channels.size(), 0);
    std::vector<bool> skipped(cfg_.channels.size(), false);

    size_t idx = 0;
    while (running_.load()) {
        // 다음 동작 가능한 채널 찾기 — 모두 skip이면 호퍼 정지
        size_t scanned = 0;
        while (skipped[idx]) {
            idx = (idx + 1) % cfg_.channels.size();
            if (++scanned >= cfg_.channels.size()) {
                std::cerr << "[!] 모든 채널 영구 실패 — channel hopping 중단\n";
                running_.store(false);
                return;
            }
        }

        const int ch = cfg_.channels[idx];
        if (setChannel(ch)) {
            currentChannel_.store(ch);
            failures[idx] = 0;
        } else {
            failures[idx]++;
            // 첫 실패만 자세히 알림 — 로그 스팸 방지
            if (failures[idx] == 1) {
                std::cerr << "[!] channel " << ch
                          << " 변경 실패 (iw 미설치/권한 부족/밴드 미지원 가능)\n";
            }
            if (failures[idx] >= PER_CHANNEL_FAIL_LIMIT) {
                skipped[idx] = true;
                std::cerr << "[!] channel " << ch << " 영구 skip ("
                          << PER_CHANNEL_FAIL_LIMIT << "회 실패)\n";
            }
        }

        // dwell만큼 대기. stop()이 cv를 notify하면 즉시 깨어남.
        // mutex는 cv 코디네이션 전용 — 공유 mutable state 보호용 아님 (running_은 atomic).
        {
            std::unique_lock<std::mutex> lock(stopMtx_);
            stopCv_.wait_for(lock, cfg_.dwell, [this] { return !running_.load(); });
        }

        idx = (idx + 1) % cfg_.channels.size();
    }
}
