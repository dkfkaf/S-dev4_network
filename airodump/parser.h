#pragma once

#include "pch.h"
#include "structs.h"

/*선언만 하는 곳*/

// 전역 AP/Station 저장소 (main.cpp에서 정의)
extern std::map<std::string, APInfo>  g_aps;  /*extern "이 변수가 다른 cpp파일에 있다는 걸 알려주는 키워드, 쓰는 이유는 자유롭게 부를려고*/
extern std::map<std::string, StaInfo> g_stas; // Station MAC을 키로 Station 탐색
extern std::mutex                     g_mtx;

// MAC → 문자열
std::string mac_to_str(const uint8_t* mac);


/*inline이 뭐죠?
inline: "함수 호출하지 말고 그냥 코드 자리에 박아넣어!" → 속도 ↑*/

// Frame Control inline helper
inline uint8_t fc_type(uint16_t fc)    { return (fc >> 2) & 0x3; }
inline uint8_t fc_subtype(uint16_t fc) { return (fc >> 4) & 0xF; }
inline uint8_t fc_tods(uint16_t fc)    { return (fc >> 8) & 0x1; }  // bit8: AP 방향으로 가는 프레임
inline uint8_t fc_fromds(uint16_t fc)  { return (fc >> 9) & 0x1; }  // bit9: AP에서 나오는 프레임

// Radiotap에서 radiotap 길이 추출
bool parse_radiotap_len(const uint8_t* pkt, int caplen, int& rt_len_out);

// Radiotap에서 신호 세기(PWR) 추출
bool parse_pwr(const uint8_t* pkt, int caplen, int8_t& signal_out);

// Beacon Tagged Parameters에서 ESSID 추출
void parse_essid(const uint8_t* p, int len, APInfo& ap);

// pcap 콜백
void packet_handler(u_char* user, const struct pcap_pkthdr* h, const u_char* pkt);