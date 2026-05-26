/* channel_hopper.cpp — ChannelHopper 구현.
   worker thread가 config.channels을 순차 순회. 각 채널마다 'iw dev <iface> set channel N'을
   fork/execlp로 호출(stderr는 errPipe로 캡처). 실패 시 채널별 재시도 지연이 점점 늘어남(1s→2s→...→5min cap).
   stop()은 condition_variable로 dwell sleep을 즉시 인터럽터블. */

#include "pch.h"
#include "channel_hopper.h"
#include <sys/wait.h>
#include <cerrno>
#include <sstream>


ChannelHopper::ChannelHopper(std::string iface, ChannelHopConfig config)
    : iface_(std::move(iface)), config_(std::move(config)) {}

ChannelHopper::~ChannelHopper() { stop(); }

bool ChannelHopper::start() {
    if (config_.channels.empty()) {
        LOG(ERROR) << "[hopper] channel list가 비어있어 channel hopper를 시작하지 않습니다";
        return false;
    }
    if (running_.exchange(true)) return true;  // 이미 실행 중 — idempotent 성공
    if (worker_.joinable()) worker_.join();
    worker_ = std::thread([this] { run(); });
    return true;
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

    constexpr size_t maxStderrBytes = 4096;   // iw의 stderr는 최대 4KB까지만 캡처 (나머지는 버림)
    std::string captured;
    char buf[256];
    for (;;) {
        ssize_t n = ::read(errPipe[0], buf, sizeof(buf));
        if (n > 0) {
            if (captured.size() < maxStderrBytes) {
                const size_t room = maxStderrBytes - captured.size();
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
    for (int ch : config_.channels) {
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
    oss << " — " << config_.dwell.count() << "ms dwell";
    return oss.str();
}

/* 채널별 지수 재시도 지연. 영구 skip 대신 실패 횟수에 따라 다음 시도 시각을 미루고,
   성공하면 카운터 reset. 일시 장애 후 복구를 허용해 채널이 영구 사라지지 않게 한다.
   1, 2, 4, 8, ... 초로 두 배씩 늘리되 5분에서 cap. */
void ChannelHopper::run() {
    using clock = std::chrono::steady_clock;
    constexpr auto initialRetryDelay = std::chrono::milliseconds(1000);
    constexpr auto maxRetryDelay  = std::chrono::milliseconds(5 * 60 * 1000);

    struct ChState {
        int                              failures = 0;
        std::optional<clock::time_point> skipUntil;
    };
    std::vector<ChState> state(config_.channels.size());

    auto computeRetryDelay = [&](int n) {
        auto delay = initialRetryDelay;
        for (int i = 1; i < n; ++i) {
            delay *= 2;
            if (delay >= maxRetryDelay) return maxRetryDelay;
        }
        return delay;
    };

    size_t idx = 0;
    while (running_.load()) {
        const auto now = clock::now();

        // 현재 idx가 재시도 지연 중이면 ready한 채널로 점프. 전부 지연 중이면 가장 이른 만료까지 대기.
        if (state[idx].skipUntil.has_value() && now < state[idx].skipUntil.value()) {
            std::optional<size_t>            readyIdx;
            std::optional<clock::time_point> earliest;
            for (size_t k = 0; k < config_.channels.size(); ++k) {
                const size_t j = (idx + k) % config_.channels.size();
                const auto&  s = state[j];
                if (!s.skipUntil.has_value() || now >= s.skipUntil.value()) {
                    readyIdx = j;
                    break;
                }
                if (!earliest.has_value() || s.skipUntil.value() < earliest.value()) {
                    earliest = s.skipUntil.value();
                }
            }
            if (readyIdx.has_value()) {
                idx = readyIdx.value();
            } else {
                const auto wait = std::chrono::duration_cast<std::chrono::milliseconds>(
                    earliest.value() - clock::now());
                if (wait.count() > 0) {
                    LOG(WARNING) << "[hopper] 모든 채널 재시도 지연 중 — "
                                 << wait.count() << "ms 대기 후 재시도";
                    sleepOrUntilStop(wait);
                }
                continue;
            }
        }

        const int ch = config_.channels[idx];
        if (setChannel(ch)) {
            currentChannel_.store(ch);
            if (state[idx].failures > 0) {
                LOG(INFO) << "[hopper] 채널 " << ch
                          << " 복구 (실패 카운터 reset, 직전 " << state[idx].failures << "회)";
            }
            state[idx].failures  = 0;
            state[idx].skipUntil = std::nullopt;
            VLOG(1) << "[hopper] 채널 전환 성공: " << ch;
        } else {
            currentChannel_.store(-1);
            state[idx].failures++;
            const auto delay     = computeRetryDelay(state[idx].failures);
            state[idx].skipUntil = clock::now() + delay;
            const auto delaySec  =
                std::chrono::duration_cast<std::chrono::seconds>(delay).count();
            LOG(WARNING) << "[hopper] 채널 " << ch << " 변경 실패 "
                         << "(연속 " << state[idx].failures << "회) — "
                         << delaySec << "s 후 재시도"
                         << " → currentChannel = -1 (unknown)";
        }

        sleepOrUntilStop(config_.dwell);
        idx = (idx + 1) % config_.channels.size();
    }
}
