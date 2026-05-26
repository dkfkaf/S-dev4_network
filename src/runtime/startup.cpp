/* startup.cpp — 프로세스 시작 시 잡일.
   CLI 사용법 출력(print_usage), --channels CSV 파싱(parse_channel_list),
   root 권한 + iw 명령 가용성 사전 진단(run_startup_diagnostics).
   파일 내부 헬퍼(valid_channel_set, exec_silent)는 anonymous namespace로 격리. */

#include "pch.h"
#include "startup.h"
#include <sys/wait.h>
#include <fcntl.h>
#include <cerrno>
#include <algorithm>
#include <sstream>
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
    int pipefd[2] = {-1, -1};
    if (::pipe(pipefd) != 0) return "";

    pid_t pid = ::fork();
    if (pid < 0) { ::close(pipefd[0]); ::close(pipefd[1]); return ""; }
    if (pid == 0) {
        ::close(pipefd[0]);
        ::dup2(pipefd[1], STDOUT_FILENO);
        int devnull = ::open("/dev/null", O_WRONLY);
        if (devnull >= 0) { ::dup2(devnull, STDERR_FILENO); ::close(devnull); }
        ::close(pipefd[1]);

        std::vector<const char*> argv;
        argv.reserve(args.size() + 2);
        argv.push_back("iw");
        for (const char* a : args) argv.push_back(a);
        argv.push_back(nullptr);
        ::execvp("iw", const_cast<char* const*>(argv.data()));
        ::_exit(127);
    }

    ::close(pipefd[1]);
    std::string out;
    char buf[512];
    for (;;) {
        ssize_t n = ::read(pipefd[0], buf, sizeof(buf));
        if (n > 0)      out.append(buf, n);
        else if (n == 0) break;
        else if (errno != EINTR) break;
    }
    ::close(pipefd[0]);

    int status = 0;
    while (::waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) return "";
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) return "";
    return out;
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
    pid_t pid = ::fork();
    if (pid < 0) return false;
    if (pid == 0) {
        int devnull = ::open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            ::dup2(devnull, STDOUT_FILENO);
            ::dup2(devnull, STDERR_FILENO);
            ::close(devnull);
        }
        std::vector<const char*> argv;
        argv.reserve(args.size() + 2);
        argv.push_back(prog);
        for (const char* a : args) argv.push_back(a);
        argv.push_back(nullptr);
        ::execvp(prog, const_cast<char* const*>(argv.data()));
        ::_exit(127);
    }
    int status = 0;
    while (::waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) return false;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
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

// 어댑터의 실제 지원 채널 조회. `iw phy phyN info`의 "* NNNN MHz [CH]" 라인 파싱.
// "disabled" 표시된 채널은 제외 (regulatory 차단 등).
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

    std::vector<int> channels;
    std::istringstream iss(info);
    std::string line;
    while (std::getline(iss, line)) {
        // 규제로 막힌 채널은 "disabled" 마킹됨 — 제외.
        if (line.find("disabled") != std::string::npos) continue;
        // "    * 2412 MHz [1] (20.0 dBm)" 같은 형식 파싱
        int freq, ch;
        if (std::sscanf(line.c_str(), " * %d MHz [%d]", &freq, &ch) == 2) {
            channels.push_back(ch);
        }
    }
    return channels;
}

