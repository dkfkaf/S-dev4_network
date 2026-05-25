# OpenWIPS Debug Guide

대상 브랜치: `sensor`
재현 환경: Linux, 무선 어댑터(monitor mode)
로깅 라이브러리: **glog (Google Logging)**

---

## glog 설정

### 설치

```bash
# Ubuntu/Debian
sudo apt-get install libgoogle-glog-dev
```

### CMakeLists.txt

```cmake
find_package(glog REQUIRED)
target_link_libraries(wips-parser glog::glog)
```

### 초기화 (main.cpp 상단)

```cpp
#include <glog/logging.h>

int main(int argc, char* argv[]) {
    google::InitGoogleLogging(argv[0]);
    FLAGS_logtostderr = true;       // stderr에도 출력
    FLAGS_log_dir = "/var/log/wips"; // 파일 저장 경로
    FLAGS_v = 1;                    // verbose 레벨
    // ...
}
```

### 로그 레벨 기준

| 레벨 | 사용 상황 |
|------|-----------|
| `LOG(INFO)` | 정상 동작 (채널 전환, 패킷 수신 등) |
| `LOG(WARNING)` | 복구 가능한 이상 (채널 변경 실패, drop 발생 등) |
| `LOG(ERROR)` | 기능 저하 (pcap 에러, iw 실패 등) |
| `LOG(FATAL)` | 즉시 종료 필요 (초기화 실패 등) |
| `VLOG(1)` | 상세 디버그 (프레임 파싱 결과 등) |

---

## Bug #1. 2.4GHz 어댑터에서 5GHz 채널 시도 → 캡처 정지

**파일**: `include/hopper/channel_hopper.h`, `src/main.cpp`

### 원인 요약
`ChannelHopConfig` 기본값에 5GHz 채널이 하드코딩되어 있어, 2.4GHz 전용 어댑터에서 실패 폭주 (약 12초 동안 패킷 0건).

### glog 적용 포인트

```cpp
// src/hopper/channel_hopper.cpp - setChannel 실패 시
if (!setChannel(ch)) {
    failures[idx]++;
    LOG(WARNING) << "[hopper] 채널 " << ch << " 변경 실패 "
                 << "(시도 " << failures[idx] << "/" << PER_CHANNEL_FAIL_LIMIT << ")";
    if (failures[idx] >= PER_CHANNEL_FAIL_LIMIT) {
        LOG(ERROR) << "[hopper] 채널 " << ch << " 영구 제외 — 밴드 미지원 또는 드라이버 거부";
    }
}
```

```cpp
// src/main.cpp - 어댑터 초기화 시
LOG(INFO) << "[init] 어댑터: " << ifname << " | 채널 목록: " << cfg.channels.size() << "개";
```

### 수정 방안
1. `iw phy <phyname> info`로 지원 채널 사전 조회 후 교집합 필터링
2. `ChannelHopConfig::twoFourOnly()` 프리셋 `{1,6,11}` 추가
3. CLI 옵션 추가: `--band 2g`, `--band 5g`, `--channels 1,6,11`
4. 첫 실패 시 즉시 skip (현재 3회 허용 → 1회로 축소 고려)

---

## Bug #2. Ctrl+C가 동작하지 않음

**파일**: `src/main.cpp`, `src/hopper/channel_hopper.cpp`

### 원인 요약
- `pcap_breakloop` 미호출 → `pcap_next_ex` 블록 상태에서 시그널 무시
- Linux에서 `to_ms=1`이 무의미 (immediate mode 미설정)
- 종료 순서 오류: capture join → hopper stop 순서가 데드락 유발
- `g_running`과 `ChannelHopper::running_`이 연결되지 않음

### glog 적용 포인트

```cpp
// 시그널 핸들러
static void on_sigint(int) {
    g_running.store(false);
    for (auto* p : g_pcaps) pcap_breakloop(p);   // 추가
    for (auto& h : g_hoppers) h->stop();          // 추가
    LOG(INFO) << "[signal] SIGINT 수신 — 종료 시작";
}
```

```cpp
// 종료 순서 변경 (main.cpp)
// 수정 전: threads join → hoppers stop
// 수정 후:
for (auto& h : hoppers) h->stop();   // 1) hopper 먼저
LOG(INFO) << "[shutdown] hopper 정지 완료";
for (auto& t : threads) t.join();    // 2) capture join
LOG(INFO) << "[shutdown] capture 스레드 종료 완료";
for (auto* p : pcaps) pcap_close(p);
LOG(INFO) << "[shutdown] pcap 핸들 해제 완료";
```

```cpp
// pcap_open_live → pcap_create로 교체
pcap_t* p = pcap_create(ifname, errbuf);
pcap_set_snaplen(p, 65535);
pcap_set_promisc(p, 1);
pcap_set_timeout(p, 100);
pcap_set_immediate_mode(p, 1);   // 추가: 즉시 깨어남
pcap_set_buffer_size(p, 4 * 1024 * 1024);
if (pcap_activate(p) != 0) {
    LOG(FATAL) << "[pcap] 활성화 실패: " << pcap_geterr(p);
}
LOG(INFO) << "[pcap] immediate mode 활성화 완료: " << ifname;
```

### 수정 방안
1. 시그널 핸들러에서 `pcap_breakloop` + `hopper->stop()` 동시 호출
2. `pcap_set_immediate_mode(p, 1)` 적용
3. 종료 순서: hopper stop → capture join → pcap close
4. `request_shutdown()` 단일 종료 함수로 통합
5. `waitpid`에서 `EINTR` 처리 추가

---

## Bug #3. `setChannel` 실패 시 `currentChannel_` stale 값 유지

**파일**: `src/hopper/channel_hopper.cpp`

### 원인 요약
채널 변경 실패 시 `currentChannel_`을 갱신하지 않아 실제 상태와 불일치.

### glog 적용 포인트

```cpp
if (setChannel(ch)) {
    currentChannel_.store(ch);
    VLOG(1) << "[hopper] 채널 전환 성공: " << ch;
} else {
    currentChannel_.store(-1);   // unknown 명시
    LOG(WARNING) << "[hopper] 채널 " << ch << " 실패 → currentChannel = -1 (unknown)";
}
```

### 수정 방안
- 실패 시 `currentChannel_.store(-1)` (unknown 표시)
- 또는 `iw dev <iface> info`로 실제 채널 재조회 후 동기화

---

## Bug #4. `iw` 실패 원인 구분 불가

**파일**: `src/hopper/channel_hopper.cpp`

### 원인 요약
`iw` 종료 코드만 확인, stderr 미캡처로 실제 원인 불명.

### glog 적용 포인트

```cpp
// iw stderr 캡처 후 로깅
if (exit_code != 0) {
    LOG(ERROR) << "[iw] 채널 " << ch << " 변경 실패"
               << " | exit_code=" << exit_code
               << " | stderr: " << captured_stderr;
}
```

```cpp
// 시작 시 사전 진단
if (geteuid() != 0) {
    LOG(FATAL) << "[init] root 권한 없음 — sudo로 실행 필요";
}
if (system("iw --version > /dev/null 2>&1") != 0) {
    LOG(FATAL) << "[init] iw 미설치 — sudo apt install iw";
}
LOG(INFO) << "[init] 사전 진단 통과";
```

### 수정 방안
- `pipe()` + `dup2()`로 `iw` stderr 캡처
- 시작 시 `iw --version`, `geteuid()`, `iw phy info` 1회 점검

---

## Bug #5. Beacon flood로 Deauth 탐지 실패

**파일**: `src/main.cpp`, `src/parser/parser.cpp`

### 원인 요약
BPF 필터가 모든 mgmt 프레임을 통과시켜, beacon 100~500fps 환경에서 kernel ring buffer overflow → deauth drop.

### glog 적용 포인트

```cpp
// BPF 필터 좁히기 (가장 효과적)
const char* filter = "type mgt and (subtype deauth or subtype disassoc)";
if (pcap_compile(pcap, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) == 0) {
    pcap_setfilter(pcap, &fp);
    LOG(INFO) << "[pcap] BPF 필터 적용: " << filter;
} else {
    LOG(ERROR) << "[pcap] BPF 컴파일 실패: " << pcap_geterr(pcap);
}
```

```cpp
// pcap_stats로 drop 모니터링 (5초마다)
pcap_stat ps;
if (pcap_stats(pcap, &ps) == 0) {
    LOG(INFO) << "[stats] received=" << ps.ps_recv
              << " dropped_kernel=" << ps.ps_drop
              << " dropped_iface="  << ps.ps_ifdrop;
    if (ps.ps_drop > 0) {
        LOG(WARNING) << "[stats] kernel drop 발생! BPF 필터 확인 필요";
    }
}
```

```cpp
// deauth 탐지 시
if (f.frameType == MGMT_SUBTYPE_DEAUTH) {
    LOG(WARNING) << "[detect] Deauth 수신 | src=" << f.src
                 << " dst=" << f.dst
                 << " channel=" << f.channel;
    for (const auto& a : detector.observe(make_deauth_event(f))) {
        LOG(ERROR) << "[alert] " << a.description;
        print_alert(a);
    }
}
```

### 수정 방안
1. **(P0)** BPF 필터를 `deauth or disassoc`으로 좁히기
2. `pcap_set_immediate_mode(p, 1)` + `pcap_set_buffer_size(p, 4MB)` 적용
3. `pcap_stats`로 drop 주기적 모니터링
4. beacon 로깅 비활성화 또는 100건당 1건 샘플링

---

## 우선순위 요약

| 순위 | Bug | 핵심 조치 |
|------|-----|-----------|
| P0 | #2 Ctrl+C 불가 | `pcap_breakloop` + immediate mode + 종료 순서 수정 |
| P0 | #5 Beacon flood | BPF 필터 `deauth/disassoc`으로 좁히기 |
| P0 | #1 5GHz 강제 시도 | `twoFourOnly()` 프리셋 + 어댑터 밴드 사전 조회 |
| P1 | #3 stale channel | 실패 시 `currentChannel_.store(-1)` |
| P2 | #4 에러 진단 | `iw` stderr 캡처 + 시작 시 사전 진단 |

---

## 검증 체크리스트

```
[ ] 2.4GHz 전용 어댑터(RTL8188EU 등)에서 12초 내 안정화
[ ] Ctrl+C 즉시 종료 (트래픽 0 상태 포함)
[ ] 5GHz 지원 어댑터에서 회귀 없음
[ ] iw 미설치 환경에서 명확한 에러 메시지 출력
[ ] AP 10개 + deauth 50pps 환경에서 BPF 적용 전후 ps_drop 비교
[ ] disassoc flood BPF 확장 동작 확인
[ ] glog 로그 파일 /var/log/wips/ 에 정상 저장
```