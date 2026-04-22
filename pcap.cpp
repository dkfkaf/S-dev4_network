#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>


#define ETHERTYPE_IP  0x0800 //ipv4사용할거니까 미리 정의해두기
#define IPPROTO_TCP_VAL 6 //우리는 tcp 쓸거니까 사전에 6으로 정의

struct libnet_ethernet_hdr {
    uint8_t  ether_dhost[6]; /* destination ethernet address */
    uint8_t  ether_shost[6]; /* source ethernet address      */
    uint16_t ether_type;     /* protocol                     */
} __attribute__((packed));


struct libnet_ipv4_hdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t ip_hl:4;  /* header length (in 32-bit words) */
    uint8_t ip_v:4;   /* version                         */
#else
    uint8_t ip_v:4;
    uint8_t ip_hl:4;
#endif
    uint8_t  ip_tos;        /* type of service      */
    uint16_t ip_len;        /* IP헤더 + 데이터 전체 길이         */
    uint16_t ip_id;         /* 단편화 식별자      */
    uint16_t ip_off;        /* 단편화 플래그 + 오프셋      */
    uint8_t  ip_ttl;        /* TTL       */
    uint8_t  ip_p;          /* 상위 프로토콜 (6 = TCP, 17 = UDP 등)            */
    uint16_t ip_sum;        /* 무결성 체크             */
    struct in_addr ip_src;  /* source address       */
    struct in_addr ip_dst;  /* destination address  */
} __attribute__((packed));

/* TCP 헤더 구조체 */
struct libnet_tcp_hdr {
    uint16_t th_sport; /* source port      */
    uint16_t th_dport; /* destination port */
    uint32_t th_seq;   /* sequence number  */
    uint32_t th_ack;   /* acknowledgement  */
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t  th_x2:4; /* unused           */
    uint8_t  th_off:4;/* data offset      */
#else
    uint8_t  th_off:4;
    uint8_t  th_x2:4;
#endif
    uint8_t  th_flags; /* control flags    */
    uint16_t th_win;   /* window           */
    uint16_t th_sum;   /* checksum         */
    uint16_t th_urp;   /* urgent pointer   */
} __attribute__((packed));

/* ============================================================
 *  Packet Handler
 * ============================================================ */
void packet_handler(u_char *,
                    const struct pcap_pkthdr *pkthdr,
                    const u_char *packet)
{
  

    /* 이더넷 파싱하는 부분이다 */
    if (pkthdr->caplen < sizeof(struct libnet_ethernet_hdr)) return; // 패킷이 너무 짧으면 버리기

    const struct libnet_ethernet_hdr *eth =
        (const struct libnet_ethernet_hdr *)packet; //packet 포인터를 이더넷 구조체로 캐스팅

    
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) return; /* 받아온 패킷을 host바이트 오더링으로 변환한뒤에 IPv4(0x0800)인지 체크 */

    /* ip 파싱하는 부분이다. */
    const u_char *ip_start = packet + sizeof(struct libnet_ethernet_hdr); //이더넷 헤더 뒤에 ip가 오기 때문에 해당 코드 작성
    if (pkthdr->caplen < sizeof(struct libnet_ethernet_hdr)  
                       + sizeof(struct libnet_ipv4_hdr)) return; //길이가 짧으면 사라져라!

    const struct libnet_ipv4_hdr *ip =
        (const struct libnet_ipv4_hdr *)ip_start;  //위에서 정의한 구조체로 파싱

   
    if (ip->ip_p != IPPROTO_TCP_VAL) return; //Tcp가 아니면 버린다. tcp=6

    uint32_t ip_hdr_len = ip->ip_hl * 4; // ip_hl은 4바이트 단위이므로 *4 해야 실제 바이트 수 보통 20임

    /* TCP 파싱하는 부분이다. */
    const u_char *tcp_start = ip_start + ip_hdr_len; //이더넷+ip 이후 tcp 시작, 위와 동일하기에 주석을 생략함
    uint32_t offset_tcp = (uint32_t)(tcp_start - packet);
    if (pkthdr->caplen < offset_tcp + sizeof(struct libnet_tcp_hdr)) return;

    const struct libnet_tcp_hdr *tcp =
        (const struct libnet_tcp_hdr *)tcp_start;

    uint32_t tcp_hdr_len = tcp->th_off * 4;

    /* 페이로드 위치 계산하는 부분: 생각해보니 이더넷,ip,tcp 이 친구들은 헤더크기가 고정이 아니어서 */
    const u_char *payload = tcp_start + tcp_hdr_len;
    uint32_t offset_payload = (uint32_t)(payload - packet);

    // payload 길이 계산
    uint32_t ip_total = ntohs(ip->ip_len);
    uint32_t payload_len = ip_total - ip_hdr_len - tcp_hdr_len;

    // 실제 캡처된 길이 초과 시 보정
    if (offset_payload > pkthdr->caplen)
        payload_len = 0;
    else if (offset_payload + payload_len > pkthdr->caplen)
        payload_len = pkthdr->caplen - offset_payload;

    /* 출력부분*/
    printf("=== TCP Packet ===\n");

    /* Ethernet */
    printf("[Ethernet]\n");
    printf("  Src MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
           eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    printf("  Dst MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
           eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

    /* IP */
    printf("[IP]\n");
    printf("  Src IP  : %s\n", inet_ntoa(ip->ip_src));
    printf("  Dst IP  : %s\n", inet_ntoa(ip->ip_dst));

    /* TCP */
    printf("[TCP]\n");
    printf("  Src Port: %u\n", ntohs(tcp->th_sport));
    printf("  Dst Port: %u\n", ntohs(tcp->th_dport));

    /* Payload */
    printf("[Payload] (%u bytes, showing up to 20)\n", payload_len);
    uint32_t show = payload_len > 20 ? 20 : payload_len;
    if (show == 0) {
        printf("  (no data)\n");
    } else {
        printf("  ");
        for (uint32_t i = 0; i < show; i++)
            printf("%02x ", payload[i]);
        printf("\n");
    }
    printf("\n");
}

/* ============================================================
 *  main
 * ============================================================ */
int main(int argc, char *argv[])         //인자 확인하고 사용법 출력하는 부분
{
    if (argc != 2) {
        fprintf(stderr, "문법: pcap-test <interface>\n");
        fprintf(stderr, "예시: pcap-test wlan0\n");
        return EXIT_FAILURE;
    }

    char errbuf[PCAP_ERRBUF_SIZE];  //에러 메시지를 담을 버퍼
    pcap_t *handle = pcap_open_live(argv[1],  //인터페이스 이름을 받아옴
                                    BUFSIZ,  /* 한번에 캡처할 최대 바이트 수  */
                                    1,       /* 무차별적 모드 실행 */
                                    1000,    /* timeout ms */
                                    errbuf);  //실패시 에러 메시지 여기에 저장
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live(%s) failed: %s\n", argv[1], errbuf);  //패킷 여는 거 실패했져용
        return EXIT_FAILURE;
    }

    /* 와이파이 패킷 잡아서 이러면 큰일 나니까 이더넷 패킷인지 확인해는 코드 */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Device %s is not an Ethernet interface\n", argv[1]);
        pcap_close(handle);
        return EXIT_FAILURE;
    }

    printf("Listening on %s ... (Ctrl+C to stop)\n\n", argv[1]);

    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    int res;

    /* pcap_loop 대신 pcap_next_ex 를 사용한 직접 루프 */
    while ((res = pcap_next_ex(handle, &header, &pkt_data)) >= 0) { //패킷 한개 잡기
        if (res == 0) continue; /* timeout */
        packet_handler(NULL, header, pkt_data); //잡은 패킷 파싱하기
    }

    if (res == -1)
        fprintf(stderr, "pcap_next_ex error: %s\n", pcap_geterr(handle));

    pcap_close(handle);
    return EXIT_SUCCESS;
}