#pragma once
#include <vector>

/* 프로세스 시작 시 호출되는 헬퍼들 — main.cpp에서 분리.
   CLI 파싱, 사전 진단, 로그 디렉토리 초기화 등 "main() 전후의 잡일" 모음. */

void print_usage();

// CSV(예: "1,6,11") → 채널 번호 vector. valid_channel_set에 없는 채널/중복은 거부.
bool parse_channel_list(const char* csv, std::vector<int>& out);

// root 권한 + iw 명령 가용성 확인. 실패 시 LOG(FATAL).
void run_startup_diagnostics();

// /var/log/wips 디렉토리 생성/확인 + glog log_dir 설정 시도.
// 성공 시 true (caller가 alsologtostderr 사용 권장).
// 실패 시 false (caller가 logtostderr로 fallback해야 함).
bool init_log_dir();
