#pragma once
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

struct ChannelHopConfig {
    // 기본값: 2.4GHz non-overlapping + 5GHz non-DFS (UNII-1, UNII-3).
    // DFS 채널(52~144)은 레이더 감지 의무로 진입 직후 passive-only 시간이 있어 캡처 효율이
    // 떨어지므로 제외. 5GHz 채널은 어댑터/드라이버가 monitor mode를 지원해야 동작하며,
    // 실패 시 ChannelHopper의 backoff(채널별 3회 실패 → 영구 skip)로 처리된다.
    std::vector<int>          channels = {
        1, 6, 11,                    // 2.4GHz
        36, 40, 44, 48,              // 5GHz UNII-1
        149, 153, 157, 161,          // 5GHz UNII-3
    };
    std::chrono::milliseconds dwell    = std::chrono::milliseconds(500);

    // 듀얼 어댑터 운용용 preset
    //   fastNonDfs : 2.4GHz + 5GHz non-DFS, 짧은 dwell — 광역 빠른 sweep
    //   dfsOnly    : 5GHz DFS 전담, 긴 dwell — CAC 비용 amortize
    static ChannelHopConfig fastNonDfs();
    static ChannelHopConfig dfsOnly();
};

// 별도 스레드에서 dwell time마다 채널을 순환시킨다.
// 채널 변경은 `iw dev <iface> set channel <n>`를 fork/execlp로 호출한다.
class ChannelHopper {
public:
    ChannelHopper(std::string iface, ChannelHopConfig cfg);
    ~ChannelHopper();

    ChannelHopper(const ChannelHopper&)            = delete;
    ChannelHopper& operator=(const ChannelHopper&) = delete;

    void start();
    void stop();

    std::optional<int> currentChannel() const;

    // 사람이 읽기 좋은 채널 구성 요약. main의 시작 배너 등에 사용.
    std::string summary() const;

private:
    void run();
    bool setChannel(int channel);

    std::string               iface_;
    ChannelHopConfig          cfg_;
    std::thread               worker_;
    std::atomic<bool>         running_{false};
    std::atomic<int>          currentChannel_{-1};

    // dwell 대기를 인터럽트하기 위한 cv (stop()에서 notify)
    std::mutex                stopMtx_;
    std::condition_variable   stopCv_;
};
