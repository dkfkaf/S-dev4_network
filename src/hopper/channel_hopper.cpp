#include "pch.h"
#include "channel_hopper.h"
#include <sys/wait.h>
#include <cerrno>
#include <sstream>


ChannelHopper::ChannelHopper(std::string iface, ChannelHopConfig cfg)
    : iface_(std::move(iface)), cfg_(std::move(cfg)) {}

ChannelHopper::~ChannelHopper() { stop(); }

void ChannelHopper::start() {
    if (cfg_.channels.empty()) {
        LOG(ERROR) << "[hopper] channel list가 비어있어 channel hopper를 시작하지 않습니다";
        return;
    }
    if (running_.exchange(true)) return;
    if (worker_.joinable()) worker_.join();
    worker_ = std::thread([this] { run(); });
}

void ChannelHopper::stop() {
    running_.store(false);
    stopCv_.notify_all();
    if (worker_.joinable()) worker_.join();
}

std::optional<int> ChannelHopper::currentChannel() const {
    int ch = currentChannel_.load();
    if (ch < 0) return std::nullopt;
    return ch;
}

bool ChannelHopper::setChannel(int channel) {
    char chBuf[16];
    std::snprintf(chBuf, sizeof(chBuf), "%d", channel);

    int errPipe[2] = {-1, -1};
    if (::pipe(errPipe) != 0) {
        LOG(ERROR) << "[iw] pipe() 실패: "
                   << std::generic_category().message(errno);
        return false;
    }

    pid_t pid = fork();
    if (pid < 0) {
        ::close(errPipe[0]);
        ::close(errPipe[1]);
        return false;
    }

    if (pid == 0) {
        ::close(errPipe[0]);
        ::dup2(errPipe[1], STDERR_FILENO);
        ::close(errPipe[1]);
        ::execlp("iw", "iw", "dev", iface_.c_str(), "set", "channel", chBuf,
                 static_cast<char*>(nullptr));
        ::_exit(127);
    }

    ::close(errPipe[1]);

    constexpr size_t kCapturedCap = 4096;
    std::string captured;
    char buf[256];
    for (;;) {
        ssize_t n = ::read(errPipe[0], buf, sizeof(buf));
        if (n > 0) {
            if (captured.size() < kCapturedCap) {
                const size_t room = kCapturedCap - captured.size();
                captured.append(buf,
                                std::min(static_cast<size_t>(n), room));
            }
            continue;
        }
        if (n == 0) break;
        if (errno != EINTR) break;
    }
    ::close(errPipe[0]);

    int status = 0;
    while (::waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) return false;
    }

    const bool ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
    if (!ok) {
        while (!captured.empty() &&
               (captured.back() == '\n' || captured.back() == '\r')) {
            captured.pop_back();
        }
        const int exitCode = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        LOG(ERROR) << "[iw] 채널 " << channel << " 변경 실패"
                   << " | exit_code=" << exitCode
                   << " | stderr: " << (captured.empty() ? "(empty)" : captured);
    }
    return ok;
}

void ChannelHopper::sleepOrUntilStop(std::chrono::milliseconds dur) {
    std::unique_lock<std::mutex> lock(stopMtx_);
    stopCv_.wait_for(lock, dur, [this] { return !running_.load(); });
}


std::string ChannelHopper::summary() const {
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

    std::vector<int>  failures(cfg_.channels.size(), 0);
    std::vector<bool> skipped(cfg_.channels.size(), false);

    size_t idx = 0;
    while (running_.load()) {
        size_t skipcount = 0;
        while (skipped[idx]) {
            idx = (idx + 1) % cfg_.channels.size();
            if (++skipcount >= cfg_.channels.size()) {
                LOG(ERROR) << "[hopper] 모든 채널 영구 실패 — channel hopping 중단";
                running_.store(false);
                return;
            }
        }

        const int ch = cfg_.channels[idx];
        if (setChannel(ch)) {
            currentChannel_.store(ch);
            failures[idx] = 0;
            VLOG(1) << "[hopper] 채널 전환 성공: " << ch;
        } else {
            currentChannel_.store(-1);
            failures[idx]++;
            LOG(WARNING) << "[hopper] 채널 " << ch << " 변경 실패 "
                         << "(시도 " << failures[idx]
                         << "/" << PER_CHANNEL_FAIL_LIMIT << ")"
                         << " → currentChannel = -1 (unknown)";
            if (failures[idx] >= PER_CHANNEL_FAIL_LIMIT) {
                skipped[idx] = true;
                LOG(ERROR) << "[hopper] 채널 " << ch
                           << " 영구 제외 — 밴드 미지원 또는 드라이버 거부 ("
                           << PER_CHANNEL_FAIL_LIMIT << "회 실패)";
            }
        }

        sleepOrUntilStop(cfg_.dwell);
        idx = (idx + 1) % cfg_.channels.size();
    }
}
