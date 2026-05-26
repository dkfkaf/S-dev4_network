/* channel_hopper.cpp — ChannelHopper 구현.
   worker thread가 config.channels을 순차 순회. 각 채널마다 'iw dev <iface> set channel N'을
   fork/execlp로 호출(stderr는 errPipe로 캡처). 미지원 채널은 startup에서 사전 필터됨 —
   여기 도달하는 채널은 어댑터 지원. 일시 실패해도 다음 cycle에 자동 재시도.
   stop()은 condition_variable로 dwell sleep을 즉시 인터럽터블. */

#include "pch.h"
#include "channel_hopper.h"
#include <sys/wait.h>
#include <cerrno>


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


namespace {
std::string joinCsv(const std::vector<int>& v) {
    std::ostringstream s;
    for (size_t i = 0; i < v.size(); ++i) {
        if (i > 0) s << ",";
        s << v[i];
    }
    return s.str();
}
}  // namespace

std::string ChannelHopper::summary() const {
    std::vector<int> ch24, ch5;
    for (int ch : config_.channels) {
        (ch <= 14 ? ch24 : ch5).push_back(ch);
    }

    std::ostringstream oss;
    if (!ch24.empty())                       oss << "2.4GHz(" << joinCsv(ch24) << ")";
    if (!ch24.empty() && !ch5.empty())       oss << " + ";
    if (!ch5.empty())                        oss << "5GHz("   << joinCsv(ch5)  << ")";
    oss << " — " << config_.dwell.count() << "ms dwell";
    return oss.str();
}

/* 단순 순환 — 시작 시 capability 필터(querySupportedChannels)로 미지원 채널은 이미 걸러짐.
   여기 도달하는 채널은 어댑터가 지원함. 일시 실패해도 다음 cycle에 자연히 재시도. */
void ChannelHopper::run() {
    size_t idx = 0;
    while (running_.load()) {
        const int ch = config_.channels[idx];
        if (setChannel(ch)) {
            VLOG(1) << "[hopper] 채널 전환 성공: " << ch;
        } else {
            LOG(WARNING) << "[hopper] 채널 " << ch << " 변경 실패 — 다음 cycle에 자동 재시도";
        }
        sleepOrUntilStop(config_.dwell);
        idx = (idx + 1) % config_.channels.size();
    }
}
