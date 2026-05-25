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
    inline static const std::vector<int> TWO_FOUR_CHANNELS = {
        1, 6, 11,
    };

    inline static const std::vector<int> NON_DFS_CHANNELS = {
        1, 6, 11,
        36, 40, 44, 48,
        149, 153, 157, 161,
    };

    inline static const std::vector<int> DFS_CHANNELS = {
        52, 56, 60, 64,
        100, 104, 108, 112, 116, 132, 136, 140,
    };

    std::vector<int>          channels = NON_DFS_CHANNELS;
    std::chrono::milliseconds dwell    = std::chrono::milliseconds(500);

    static ChannelHopConfig twoFourOnly() {
        return {TWO_FOUR_CHANNELS, std::chrono::milliseconds(300)};
    }
    static ChannelHopConfig fastNonDfs() {
        return {NON_DFS_CHANNELS, std::chrono::milliseconds(200)};
    }
    static ChannelHopConfig dfsOnly() {
        return {DFS_CHANNELS, std::chrono::milliseconds(2000)};
    }
};

class ChannelHopper {
public:
    ChannelHopper(std::string iface, ChannelHopConfig cfg);
    ~ChannelHopper();

    ChannelHopper(const ChannelHopper&)            = delete;
    ChannelHopper& operator=(const ChannelHopper&) = delete;

    void start();
    void stop();

    std::optional<int> currentChannel() const;

    std::string summary() const;

private:
    void run();
    bool setChannel(int channel);
    void sleepOrUntilStop(std::chrono::milliseconds dur);

    std::string               iface_;
    ChannelHopConfig          cfg_;
    std::thread               worker_;
    std::atomic<bool>         running_{false};
    std::atomic<int>          currentChannel_{-1};

    std::mutex                stopMtx_;
    std::condition_variable   stopCv_;
};
