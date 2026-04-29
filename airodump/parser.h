#pragma once

#include "pch.h"
#include "structs.h"

extern std::map<std::string, APInfo>  g_aps;
extern std::map<std::string, StaInfo> g_stas;
extern std::mutex                     g_mtx;

std::string mac_to_str(const uint8_t* mac);

inline uint8_t fc_type(uint16_t fc)    { return (fc >> 2) & 0x3; }
inline uint8_t fc_subtype(uint16_t fc) { return (fc >> 4) & 0xF; }
inline uint8_t fc_tods(uint16_t fc)    { return (fc >> 8) & 0x1; }
inline uint8_t fc_fromds(uint16_t fc)  { return (fc >> 9) & 0x1; }

bool parse_radiotap_len(const uint8_t* pkt, int caplen, int& rt_len_out);
bool parse_pwr(const uint8_t* pkt, int caplen, int8_t& signal_out);
void parse_essid(const uint8_t* p, int len, APInfo& ap);
void packet_handler(u_char* user, const struct pcap_pkthdr* h, const u_char* pkt);
