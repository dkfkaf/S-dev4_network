#pragma once
#include <memory>
#include <string>
#include <vector>
#include "channel_hopper.h"

/* 프로세스 시작 시 호출되는 헬퍼들 — main.cpp에서 분리.
   CLI 파싱, 사전 진단, 어댑터 셋업, 배너 출력 등 "main() 전후의 잡일" 모음. */

void print_usage();

// CSV(예: "1,6,11") → 채널 번호 vector. valid_channel_set에 없는 채널/중복은 거부.
bool parse_channel_list(const char* csv, std::vector<int>& out);

// root 권한 + iw 명령 가용성 확인. 실패 시 LOG(FATAL).
void run_startup_diagnostics();

// `iw dev <iface> info` + `iw phy phyN info`로 어댑터가 실제 지원하는 채널 번호 조회.
// 실패 시(파싱 불가, iw 미설치 등) 빈 vector — caller가 fallback으로 config 그대로 사용.
std::vector<int> querySupportedChannels(const std::string& iface);

// `iw phy N info` 출력 문자열에서 지원 채널 추출 — 순수 함수, 테스트 가능.
// "    * NNNN MHz [CH]" 라인 파싱, "disabled" 표시 채널은 제외.
std::vector<int> parseChannelsFromIwPhyInfo(const std::string& iwOutput);

// ─── CLI/어댑터 셋업 (main.cpp 단순화용) ──────────────────────────────────────

struct CliOpts {
    enum class Band { all, twoFour, five };

    Band                     band = Band::all;
    std::vector<int>         customChannels;
    std::vector<std::string> positionalIfnames;
    bool                     parseOk          = true;   // false면 main 즉시 exit(1)
    bool                     showHelpAndExit  = false;  // --help → exit(0)
};

// argc/argv → CliOpts. 잘못된 옵션은 print_usage 호출 후 parseOk=false.
CliOpts parse_cli(int argc, char* argv[]);

struct AdapterSetup {
    std::string      ifname;
    std::string      label;   // dual-adapter 시 "fast"/"dfs", single이면 빈 문자열
    ChannelHopConfig config;
};

// CliOpts → AdapterSetup 리스트 (capability 필터까지 적용).
// 실패(positional 개수 잘못, 중복 iface, 미지원 채널 전부)면 빈 vector.
std::vector<AdapterSetup> build_adapters(const CliOpts& opts);

// 시작 시 운영자에게 보여주는 배너 — mode/iface/policy 요약.
void print_banner(const std::vector<AdapterSetup>&                    adapters,
                  const std::vector<std::unique_ptr<ChannelHopper>>&  hoppers,
                  const std::vector<std::string>&                     detectorPolicyLines);
