#include "pch.h"
#include "startup.h"
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <cerrno>
#include <algorithm>
#include <unordered_set>

namespace {

const std::vector<int>& valid_channel_set() {
    static const std::vector<int> kValid = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
        36, 40, 44, 48,
        52, 56, 60, 64,
        100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
        149, 153, 157, 161, 165,
    };
    return kValid;
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

bool init_log_dir() {
    const char* path = "/var/log/wips";
    if (::mkdir(path, 0755) == 0 || errno == EEXIST) {
        FLAGS_log_dir = path;
        return true;
    }
    std::cerr << "[init] " << path << " 사용 불가 ("
              << std::generic_category().message(errno)
              << ") — stderr 전용 로깅\n";
    return false;
}
