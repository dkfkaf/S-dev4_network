/* channel_hopper.cpp — ChannelHopper 구현.
   worker thread가 config.channels을 순차 순회. 각 채널마다 `iw dev <iface> set channel N`을
   run_subprocess로 호출 (stderr 캡처). 미지원 채널은 startup에서 사전 필터됨 —
   여기 도달하는 채널은 어댑터 지원. 일시 실패해도 다음 cycle에 자동 재시도.
   stop()은 condition_variable로 dwell sleep을 즉시 인터럽터블. */

#include "pch.h"
#include "channel_hopper.h"
#include "subprocess.h"


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
    SubprocessOpts opts; opts.captureStderr = true;
    auto r = run_subprocess({"iw", "dev", iface_, "set", "channel",
                             std::to_string(channel)}, opts);
    if (r.succeeded()) return true;

    std::string err = r.stderrText;
    while (!err.empty() && (err.back() == '\n' || err.back() == '\r')) err.pop_back();
    LOG(ERROR) << "[iw] 채널 " << channel << " 변경 실패"
               << " | exit_code=" << r.exitCode
               << " | stderr: " << (err.empty() ? "(empty)" : err);
    return false;
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
