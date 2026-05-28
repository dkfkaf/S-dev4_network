/* startup.cpp — 프로세스 시작 시 잡일 모음.
   - CLI: print_usage, parse_channel_list, parse_cli
   - 진단: run_startup_diagnostics (root + iw 가용성)
   - iw capability 조회: querySupportedChannels, parseChannelsFromIwPhyInfo
   - 어댑터 셋업: build_adapters (capability 필터 포함)
   - 배너: print_banner
   외부 명령 호출은 run_subprocess(subprocess.cpp)에 위임 — fork/exec/pipe 직접 X. */

#include "pch.h"
#include "startup.h"
#include "subprocess.h"
#include <algorithm>
#include <unordered_set>

namespace {

const std::vector<int>& valid_channel_set() {
    static const std::vector<int> validChannels = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
        36, 40, 44, 48,
        52, 56, 60, 64,
        100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
        149, 153, 157, 161, 165,
    };
    return validChannels;
}

// `iw <args>` 실행해서 stdout 캡처. 실패면 빈 문자열.
std::string captureIwStdout(std::initializer_list<const char*> args) {
    std::vector<std::string> argv = {"iw"};
    for (const char* a : args) argv.emplace_back(a);
    SubprocessOpts opts; opts.captureStdout = true;
    auto r = run_subprocess(argv, opts);
    return r.succeeded() ? r.stdoutText : "";
}

// `iw dev <iface> info` 출력에서 "wiphy N" 라인의 N 추출.
std::string findWiphyIndex(const std::string& iface) {
    auto out = captureIwStdout({"dev", iface.c_str(), "info"});
    std::istringstream iss(out);
    std::string line;
    while (std::getline(iss, line)) {
        const std::string key = "wiphy ";
        auto pos = line.find(key);
        if (pos != std::string::npos) {
            std::string idx = line.substr(pos + key.size());
            // trim trailing whitespace
            while (!idx.empty() && std::isspace(static_cast<unsigned char>(idx.back()))) idx.pop_back();
            return idx;
        }
    }
    return "";
}

bool exec_silent(const char* prog, std::initializer_list<const char*> args) {
    std::vector<std::string> argv = {prog};
    for (const char* a : args) argv.emplace_back(a);
    return run_subprocess(argv).succeeded();   // 캡처 옵션 모두 false → /dev/null
}

}  // namespace

void print_usage() {
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

bool parse_channel_list(const char* csv, std::vector<int>& out) {
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

void run_startup_diagnostics() {
    if (::geteuid() != 0) {
        LOG(FATAL) << "[init] root 권한 없음 — sudo로 실행 필요";
    }
    if (!exec_silent("iw", {"--version"})) {
        LOG(FATAL) << "[init] iw 미설치 — sudo apt install iw 후 재시도";
    }
    LOG(INFO) << "[init] 사전 진단 통과 (root + iw 확인)";
}

// 순수 파싱 — `iw phy info` 출력에서 채널 번호 추출. I/O 없어 단위 테스트 가능.
std::vector<int> parseChannelsFromIwPhyInfo(const std::string& iwOutput) {
    std::vector<int> channels;
    std::istringstream iss(iwOutput);
    std::string line;
    while (std::getline(iss, line)) {
        // 규제로 막힌 채널은 "disabled" 마킹됨 — 제외.
        if (line.find("disabled") != std::string::npos) continue;
        // "    * 2412 MHz [1] (20.0 dBm)" 같은 형식 파싱. MHz는 매칭만 하고 버림(%*d).
        int ch;
        if (std::sscanf(line.c_str(), " * %*d MHz [%d]", &ch) == 1) {
            channels.push_back(ch);
        }
    }
    return channels;
}

// 어댑터의 실제 지원 채널 조회. I/O 부분 — 위 순수 파서를 호출.
std::vector<int> querySupportedChannels(const std::string& iface) {
    auto wiphy = findWiphyIndex(iface);
    if (wiphy.empty()) {
        LOG(WARNING) << "[init] iface=" << iface << " wiphy 조회 실패 — 채널 자동 필터 skip";
        return {};
    }
    const std::string phyName = "phy" + wiphy;
    auto info = captureIwStdout({"phy", phyName.c_str(), "info"});
    if (info.empty()) {
        LOG(WARNING) << "[init] " << phyName << " info 조회 실패 — 채널 자동 필터 skip";
        return {};
    }
    auto channels = parseChannelsFromIwPhyInfo(info);
    if (channels.empty()) {
        LOG(WARNING) << "[init] " << phyName
                     << " info 파싱 결과 0개 채널 — iw 출력 형식 변경 의심";
    }
    return channels;
}

// ─── CLI/어댑터 셋업 ─────────────────────────────────────────────────────────

CliOpts parse_cli(int argc, char* argv[]) {
    CliOpts opts;
    for (int i = 1; i < argc; ++i) {
        const char* a = argv[i];
        if (std::strcmp(a, "--help") == 0 || std::strcmp(a, "-h") == 0) {
            print_usage();
            opts.showHelpAndExit = true;
            return opts;
        }
        if (std::strcmp(a, "--band") == 0 && i + 1 < argc) {
            const char* v = argv[++i];
            if      (std::strcmp(v, "2g")  == 0) opts.band = CliOpts::Band::twoFour;
            else if (std::strcmp(v, "5g")  == 0) opts.band = CliOpts::Band::five;
            else if (std::strcmp(v, "all") == 0) opts.band = CliOpts::Band::all;
            else {
                std::cerr << "[init] 알 수 없는 --band 값: " << v << "\n";
                print_usage();
                opts.parseOk = false;
                return opts;
            }
        } else if (std::strcmp(a, "--channels") == 0 && i + 1 < argc) {
            if (!parse_channel_list(argv[++i], opts.customChannels)) {
                LOG(ERROR) << "[init] --channels 파싱 실패: " << argv[i];
                opts.parseOk = false;
                return opts;
            }
        } else if (a[0] == '-') {
            std::cerr << "[init] 알 수 없는 옵션: " << a << "\n";
            print_usage();
            opts.parseOk = false;
            return opts;
        } else {
            opts.positionalIfnames.emplace_back(a);
        }
    }
    return opts;
}

namespace {

// CliOpts → 기본 ChannelHopConfig (capability 필터 전).
ChannelHopConfig pickConfigForSingle(const CliOpts& opts) {
    if (!opts.customChannels.empty()) {
        ChannelHopConfig c;
        c.channels = opts.customChannels;
        c.dwell    = std::chrono::milliseconds(500);
        return c;
    }
    switch (opts.band) {
        case CliOpts::Band::twoFour: return ChannelHopConfig::twoFourOnly();
        case CliOpts::Band::five:    return ChannelHopConfig::fastNonDfs();
        case CliOpts::Band::all:
        default:                     return ChannelHopConfig{};
    }
}

// 한 어댑터의 채널 목록을 그 어댑터가 실제 지원하는 것만으로 필터.
// 전부 미지원이면 false 반환 (호출자가 종료 판단).
bool applyCapabilityFilter(AdapterSetup& a) {
    auto supported = querySupportedChannels(a.ifname);
    if (supported.empty()) return true;  // 조회 실패 — fallback으로 config 그대로 사용

    std::unordered_set<int> supportedSet(supported.begin(), supported.end());
    std::vector<int> filtered;
    for (int ch : a.config.channels) {
        if (supportedSet.count(ch)) filtered.push_back(ch);
    }
    const size_t before = a.config.channels.size();
    if (filtered.size() != before) {
        LOG(INFO) << "[init] iface=" << a.ifname
                  << " 지원 채널 자동 필터: " << before << "개 → " << filtered.size() << "개"
                  << " (어댑터 미지원 " << (before - filtered.size()) << "개 제외)";
    }
    if (filtered.empty()) {
        LOG(ERROR) << "[init] iface=" << a.ifname << " 설정 채널 전부 미지원 — 종료";
        return false;
    }
    a.config.channels = std::move(filtered);
    return true;
}

}  // namespace

std::vector<AdapterSetup> build_adapters(const CliOpts& opts) {
    std::vector<AdapterSetup> adapters;
    const auto& pos = opts.positionalIfnames;

    if (pos.size() == 1) {
        adapters.push_back({pos[0], "", pickConfigForSingle(opts)});
    } else if (pos.size() == 2) {
        if (pos[0] == pos[1]) {
            LOG(ERROR) << "[init] fast-iface와 dfs-iface는 달라야 합니다: " << pos[0];
            return {};
        }
        adapters.push_back({pos[0], "fast", ChannelHopConfig::fastNonDfs()});
        adapters.push_back({pos[1], "dfs",  ChannelHopConfig::dfsOnly()});
    } else {
        print_usage();
        return {};
    }

    for (auto& a : adapters) {
        if (!applyCapabilityFilter(a)) return {};
        LOG(INFO) << "[init] 어댑터: " << a.ifname
                  << " | 채널 목록: " << a.config.channels.size() << "개";
    }
    return adapters;
}

void print_banner(const std::vector<AdapterSetup>&                    adapters,
                  const std::vector<std::unique_ptr<ChannelHopper>>&  hoppers,
                  const std::vector<std::string>&                     detectorPolicyLines) {
    std::cout << "[*] mode          : "
              << (adapters.size() == 1 ? "single-adapter" : "dual-adapter") << "\n";
    for (size_t i = 0; i < adapters.size(); ++i) {
        std::cout << "[*] ";
        if (!adapters[i].label.empty()) std::cout << adapters[i].label << "-iface : ";
        else                            std::cout << "interface     : ";
        std::cout << adapters[i].ifname << " — " << hoppers[i]->summary() << "\n";
    }
    for (size_t i = 0; i < detectorPolicyLines.size(); ++i) {
        std::cout << (i == 0 ? "[*] deauth policy : " : "[*]                 ")
                  << detectorPolicyLines[i] << "\n";
    }
    std::cout << "[*]                 정상 disconnect(reason 3/8)는 모든 카운터에서 완전 제외 (alert 없음)\n"
              << "[*] 802.11 management frame 캡처 시작 ... (Ctrl+C to stop)\n";
}
