#pragma once
#include <string>
#include <vector>

/* fork+exec 공통 헬퍼 — channel_hopper와 startup의 외부 명령 호출 패턴 통합.
   stdout/stderr 캡처 옵션, 안 한 stream은 /dev/null로 redirect. 캡처 상한으로 OOM 방지. */

struct SubprocessResult {
    bool        spawned  = false;   // fork() 자체 성공 여부
    bool        exited   = false;   // WIFEXITED — false면 시그널/비정상 종료
    int         exitCode = -1;      // WEXITSTATUS — exited=true일 때만 의미
    std::string stdoutText;
    std::string stderrText;

    bool succeeded() const { return spawned && exited && exitCode == 0; }
};

struct SubprocessOpts {
    bool   captureStdout   = false;  // false면 /dev/null
    bool   captureStderr   = false;  // false면 /dev/null
    size_t maxCaptureBytes = 4096;   // 스트림당 캡처 상한
};

// argv[0] = 실행 파일명. PATH 검색됨 ("iw" 같은 짧은 이름 OK).
// 두 stream 동시 캡처 시 poll()로 다중화 — 한쪽 pipe buffer 가득 차서 deadlock 안 남.
SubprocessResult run_subprocess(const std::vector<std::string>& argv,
                                const SubprocessOpts&           opts = {});
