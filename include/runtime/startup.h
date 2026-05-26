#pragma once
#include <string>
#include <vector>

/* 프로세스 시작 시 호출되는 헬퍼들 — main.cpp에서 분리.
   CLI 파싱, 사전 진단, 로그 디렉토리 초기화 등 "main() 전후의 잡일" 모음. */

void print_usage();

// CSV(예: "1,6,11") → 채널 번호 vector. valid_channel_set에 없는 채널/중복은 거부.
bool parse_channel_list(const char* csv, std::vector<int>& out);

// root 권한 + iw 명령 가용성 확인. 실패 시 LOG(FATAL).
void run_startup_diagnostics();

// `iw dev <iface> info` + `iw phy phyN info`로 어댑터가 실제 지원하는 채널 번호 조회.
// 실패 시(파싱 불가, iw 미설치 등) 빈 vector — caller가 fallback으로 config 그대로 사용.
std::vector<int> querySupportedChannels(const std::string& iface);
