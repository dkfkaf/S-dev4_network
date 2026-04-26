#include "pch.h"
#include "structs.h"
#include "parser.h"

// 전역 변수 정의
std::map<std::string, APInfo> g_aps;
std::mutex                    g_mtx; /*pcap handler랑 pcap print가 동시에 접근하면 충돌이 나기 때무*/
std::atomic<bool>             g_running(true); /*원자성을 보장하는거임, 스레드 충돌을 방지하기 위해!<- 근데 운영체제 벌써
가물가물하다 어캄..?*/

// 1초마다 화면 출력

/*lock_guard → "내가 출력하는 동안 아무도 g_aps 건드리지 마"
for (auto& kv) → "저장된 AP 목록을 하나씩 꺼내와"
const APInfo& a → "꺼낸 AP 정보를 a로 편하게 접근"*/

/*.load는 읽기, .store은 쓰기*/
/*이 파일 안에서만 보이게 하기 위함 (다른 .cpp에서 못 부름)*/

/*const는 읽기 전용임*/

/*kv.first;   // 키   → BSSID (std::string)
kv.second;  // 값   → APInfo (구조체)*/
static void print_loop() {
    while (g_running.load()) {
        {
            std::lock_guard<std::mutex> lk(g_mtx);
            printf(" S-dev airodump\n\n");
            printf(" %-17s  %8s  %s\n",
                   "BSSID", "Beacons", "ESSID");
            printf(" -------------------------------------------------\n");
            for (auto& kv : g_aps) { //g_aps 처음부터 끝까지 순회
                const APInfo& a = kv.second;
                printf(" %-17s  %8d  %s\n",
                       a.bssid.c_str(), a.beacons, a.essid.c_str());
            }
        }
        sleep(1);
         /*근데 이렇게 쓰면 리눅스에서만 돌아간다... 근데 꼭 윈도우도 고려해야할까?
         크로스플랫폼 sleep 코드: std::this_thread::sleep_for(std::chrono::milliseconds(500));*/
    }
}


int main(int argc, char* argv[]) {
    const char* dev = argv[1]; /*인터페이스가 들어가는 자리*/

     if (argc != 2) {
        fprintf(stderr, "syntax : airodump <interface>\n");
        fprintf(stderr, "sample : airodump mon0\n");
        return EXIT_FAILURE;
    }

    /*pcap_open_live(
    dev,      // 1. 캡처할 네트워크 인터페이스 이름 (예: "eth0", "wlan0")
    BUFSIZ,   // 2. 캡처할 패킷의 최대 바이트 수 (스냅샷 길이), 보통 65535
    1,        // 3. 프로미스큐어스 모드 (1 = 활성화, 0 = 비활성화)
    1000,     // 4. 읽기 타임아웃 (밀리초 단위, 여기선 1초)
    errbuf    // 5. 오류 발생 시 메시지를 저장할 버퍼 (PCAP_ERRBUF_SIZE 크기)
);*/

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!pcap) {
        fprintf(stderr, "pcap_open_live(%s) failed: %s\n", dev, errbuf);
        return 1;
    }


    /*pcap_datalink(
    pcap  // 캡처 핸들 (pcap_open_live()로 반환된 pcap_t* 포인터));
    //  이 네트워크 장치가 이더넷이야? 와이파이야? 등을 확인하는 함수*/

    /*127은 DLT_IEEE802_11 로, 무선 LAN (Wi-Fi, 802.11) */

    if (pcap_datalink(pcap) != 127) { /*DLT_IEEE802_11_RADIO->대신 멘토님이 알려주신 상수 127로 채워넣기*/
        fprintf(stderr, "[!] %s is not in monitor(radiotap) mode.\n", dev);
        fprintf(stderr, "    sudo airmon-ng start <iface>\n");
        pcap_close(pcap);
        return 1;
    }

    /*std::thread t_print(print_loop);는 print_loop 함수를 별도의 스레드에서 실행하는 코드입니다.
    그래서 패킷을 잡으면서도 출력도 가능*/
    std::thread t_print(print_loop); //이 친구 스레드


    /*pcap_loop(
    pcap,            // 캡처 핸들
    0,               // 캡처할 패킷 수 (0 = 무한 반복)
    packet_handler,  // 패킷이 잡힐 때마다 호출할 콜백 함수
    nullptr          // 콜백 함수에 전달할 추가 데이터 (없으면 nullptr)
);*/
    pcap_loop(pcap, 0, packet_handler, nullptr);

    g_running.store(false); // 전역 atomic 변수를 false로 설정 (스레드 종료 신호) == 모든 스레드 멈춰!임
    t_print.join(); // t_print 스레드가 완전히 끝날 때까지 기다림
    pcap_close(pcap);
    return 0;
}