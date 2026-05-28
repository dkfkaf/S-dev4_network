/* subprocess.cpp — run_subprocess 구현.
   pipe/fork/dup2/poll/waitpid 일체를 한 곳에 모음. 캡처 안 한 stream은 /dev/null. */

#include "pch.h"
#include "subprocess.h"
#include <fcntl.h>
#include <poll.h>
#include <sys/wait.h>
#include <unistd.h>
#include <algorithm>
#include <cerrno>

namespace {

void closeIfOpen(int& fd) {
    if (fd >= 0) { ::close(fd); fd = -1; }
}

void closePipe(int (&p)[2]) {
    closeIfOpen(p[0]);
    closeIfOpen(p[1]);
}

// 자식 측: capture 요청된 stream은 pipe write end로, 아니면 /dev/null로 redirect.
void redirectStdStream(int targetFd, int pipeWriteEnd, int devnull) {
    if (pipeWriteEnd >= 0) {
        ::dup2(pipeWriteEnd, targetFd);
    } else if (devnull >= 0) {
        ::dup2(devnull, targetFd);
    }
}

}  // namespace

SubprocessResult run_subprocess(const std::vector<std::string>& argv,
                                const SubprocessOpts&           opts) {
    SubprocessResult result;
    if (argv.empty()) return result;

    int outPipe[2] = {-1, -1};
    int errPipe[2] = {-1, -1};
    if (opts.captureStdout && ::pipe(outPipe) != 0) return result;
    if (opts.captureStderr && ::pipe(errPipe) != 0) {
        closePipe(outPipe);
        return result;
    }

    const pid_t pid = ::fork();
    if (pid < 0) {
        closePipe(outPipe);
        closePipe(errPipe);
        return result;
    }

    if (pid == 0) {
        // 자식: 부모가 쓰는 read end는 닫고, write end를 stdout/stderr에 연결.
        closeIfOpen(outPipe[0]);
        closeIfOpen(errPipe[0]);
        const int devnull = ::open("/dev/null", O_WRONLY);
        redirectStdStream(STDOUT_FILENO, outPipe[1], devnull);
        redirectStdStream(STDERR_FILENO, errPipe[1], devnull);
        closeIfOpen(outPipe[1]);
        closeIfOpen(errPipe[1]);
        if (devnull >= 0) ::close(devnull);

        std::vector<const char*> cargv;
        cargv.reserve(argv.size() + 1);
        for (const auto& s : argv) cargv.push_back(s.c_str());
        cargv.push_back(nullptr);
        ::execvp(cargv[0], const_cast<char* const*>(cargv.data()));
        ::_exit(127);
    }

    // 부모: write end는 자식만 씀 — 닫아야 read에서 EOF 감지 가능.
    result.spawned = true;
    closeIfOpen(outPipe[1]);
    closeIfOpen(errPipe[1]);

    // 두 pipe 동시 read — poll로 다중화 (한쪽 buffer 가득 차서 deadlock 방지).
    struct pollfd fds[2] = {};
    int nfds = 0;
    const int outIdx = opts.captureStdout ? nfds++ : -1;
    const int errIdx = opts.captureStderr ? nfds++ : -1;
    if (outIdx >= 0) fds[outIdx] = {outPipe[0], POLLIN, 0};
    if (errIdx >= 0) fds[errIdx] = {errPipe[0], POLLIN, 0};

    int active = nfds;
    while (active > 0) {
        const int n = ::poll(fds, nfds, -1);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        for (int i = 0; i < nfds; ++i) {
            if (fds[i].fd < 0) continue;
            if (!(fds[i].revents & (POLLIN | POLLHUP | POLLERR))) continue;

            char buf[256];
            const ssize_t r = ::read(fds[i].fd, buf, sizeof(buf));
            if (r > 0) {
                std::string& dst = (i == outIdx) ? result.stdoutText : result.stderrText;
                if (dst.size() < opts.maxCaptureBytes) {
                    const size_t room = opts.maxCaptureBytes - dst.size();
                    dst.append(buf, std::min(static_cast<size_t>(r), room));
                }
            } else if (r == 0 || (r < 0 && errno != EINTR)) {
                ::close(fds[i].fd);
                fds[i].fd = -1;
                --active;
            }
        }
    }
    // poll 루프에서 모든 fd 닫혔거나 break됐음 — 혹시 남았을지 모를 fd 정리.
    closeIfOpen(outPipe[0]);
    closeIfOpen(errPipe[0]);

    int status = 0;
    while (::waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) return result;
    }
    if (WIFEXITED(status)) {
        result.exited   = true;
        result.exitCode = WEXITSTATUS(status);
    }
    return result;
}
