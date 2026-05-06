#pragma once

#include <cstdint>
#include <string>
#include <vector>

// RadioHdr: 802.11 pcap 파일의 RadioTap 헤더를 파싱하는 클래스
// 각 패킷의 안테나 신호 세기(power)와 FCS 존재 여부를 추출한다.
class RadioHdr {
public:
    // pcap 파일을 불러와 모든 패킷의 RadioTap 헤더를 파싱한다.
    // 성공 시 true, 실패 시 false 반환.
    bool loadPcap(const std::string& filename);

    // pkt_index 번째 패킷(0-based)의 안테나 수신 신호 세기(dBm)를 반환한다.
    // 해당 필드가 없거나 인덱스가 범위를 벗어나면 INT8_MIN을 반환한다.
    int8_t getPower(int pkt_index) const;

    // pkt_index 번째 패킷(0-based)에 FCS(Frame Check Sequence)가 붙어 있으면 true를 반환한다.
    // Flags 필드가 없거나 인덱스가 범위를 벗어나면 false를 반환한다.
    bool hasFCS(int pkt_index) const;

    // 로드된 패킷 수를 반환한다.
    int getPacketCount() const;

private:
    // 패킷 하나에서 추출한 RadioTap 정보
    struct PacketInfo {
        int8_t  power;        // dBm Antenna Signal
        bool    has_fcs;      // Flags 필드의 FCS 비트
        bool    power_valid;  // power 필드가 실제로 존재하는지
    };

    std::vector<PacketInfo> m_packets;

    // RadioTap 헤더 파싱 (data: 패킷 시작 포인터, len: 패킷 길이)
    void parseRadiotap(const uint8_t* data, size_t len, PacketInfo& out);
};
