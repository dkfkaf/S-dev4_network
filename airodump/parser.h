#pragma once

#include "pch.h"
#include "structs.h"

/*선언만 하는 곳*/

// 전역 AP 저장소 (main.cpp에서 정의)
extern std::map<std::string, APInfo> g_aps;   /*extern "이 변수가 다른 cpp파일에 있다는 걸 알려주는 키워드, 쓰는 이유는 자유롭게 부를려고*/
extern std::mutex                    g_mtx; /*mac값을 키로 ap 탐색*/

// MAC → 문자열
std::string mac_to_str(const uint8_t* mac);


/*static inline이 뭐죠?
inline: "함수 호출하지 말고 그냥 코드 자리에 박아넣어!" → 속도 ↑
static: "이 파일 안에서만 보여" → 헤더에 정의해도 링커 에러 안 남<-...? 왜?*/

// Frame Control inline helper
static inline uint8_t fc_type(uint16_t fc)    { return (fc >> 2) & 0x3; }
static inline uint8_t fc_subtype(uint16_t fc) { return (fc >> 4) & 0xF; }

// Radiotap에서 radiotap 길이 추출
bool parse_radiotap_len(const uint8_t* pkt, int caplen, int& rt_len_out);

// Beacon Tagged Parameters에서 ESSID 추출
void parse_essid(const uint8_t* p, int len, APInfo& ap);

// pcap 콜백
void packet_handler(u_char* user,
                    const struct pcap_pkthdr* h,
                    const u_char* pkt);