#include "radiohdr.h"

#include <cstdio>

// ---------------------------------------------
//  pcap 파일 포맷 상수
// ---------------------------------------------
static const uint32_t PCAP_MAGIC_LE    = 0xA1B2C3D4u; // 리틀엔디언 (표준)
static const uint32_t PCAP_MAGIC_BE    = 0xD4C3B2A1u; // 빅엔디언   (표준)
static const uint32_t PCAP_MAGIC_NS_LE = 0xA1B23C4Du; // 리틀엔디언 (나노초)
static const uint32_t PCAP_MAGIC_NS_BE = 0x4D3CB2A1u; // 빅엔디언   (나노초)

static const int LINKTYPE_IEEE802_11_RADIOTAP = 127;

// ---------------------------------------------
//  RadioTap present 비트 위치
// ---------------------------------------------
static const uint32_t RT_BIT_TSFT    = 1u;
static const uint32_t RT_BIT_FLAGS   = (1u << 1);
static const uint32_t RT_BIT_RATE    = (1u << 2);
static const uint32_t RT_BIT_CHANNEL = (1u << 3);
static const uint32_t RT_BIT_FHSS    = (1u << 4);
static const uint32_t RT_BIT_SIGNAL  = (1u << 5);
static const uint32_t RT_BIT_EXT     = (1u << 31); // present 필드 확장 비트

// RadioTap Flags 필드 내 FCS 비트
static const uint8_t RT_FLAG_FCS = 0x10;

// ---------------------------------------------
//  유틸: 리틀엔디언 읽기 (정렬 무관)
// ---------------------------------------------
static inline uint16_t read_u16le(const uint8_t* p) {
    return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
}
static inline uint32_t read_u32le(const uint8_t* p) {
    return static_cast<uint32_t>(p[0])
         | (static_cast<uint32_t>(p[1]) << 8)
         | (static_cast<uint32_t>(p[2]) << 16)
         | (static_cast<uint32_t>(p[3]) << 24);
}
static inline uint32_t read_u32be(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24)
         | (static_cast<uint32_t>(p[1]) << 16)
         | (static_cast<uint32_t>(p[2]) << 8)
         |  static_cast<uint32_t>(p[3]);
}

// ---------------------------------------------
//  RadioTap 헤더 파싱
//
//  RadioTap 헤더 구조 (모두 리틀엔디언):
//    [0]     it_version   (1 byte)
//    [1]     it_pad       (1 byte)
//    [2-3]   it_len       (2 bytes) - 헤더 전체 길이
//    [4-7]   it_present   (4 bytes) - 존재하는 필드 비트맵
//    [8+]    확장 present 워드들 (bit31 이 1이면 다음 4바이트도 present)
//    그 뒤로 각 필드가 정렬 규칙에 따라 순서대로 나열됨
//
//  각 필드의 정렬 요구사항:
//    TSFT    (bit0): 8바이트 정렬, 8바이트
//    Flags   (bit1): 정렬 없음,   1바이트
//    Rate    (bit2): 정렬 없음,   1바이트
//    Channel (bit3): 2바이트 정렬, 4바이트 (주파수 2B + 플래그 2B)
//    FHSS    (bit4): 정렬 없음,   2바이트
//    Signal  (bit5): 정렬 없음,   1바이트 (signed, dBm)
// ---------------------------------------------
void RadioHdr::parseRadiotap(const uint8_t* data, size_t len, PacketInfo& out) {
    out = {0, false, false};

    // 최소 8바이트 (version + pad + it_len + it_present)
    if (len < 8) return;

    uint16_t rt_len = read_u16le(data + 2);
    if (rt_len > len) return;

    // present 워드 읽기 (bit31 이 set이면 뒤에 확장 present 워드가 있음)
    uint32_t main_present = read_u32le(data + 4);
    size_t off = 8;

    // 확장 present 워드 건너뛰기
    uint32_t pw = main_present;
    while ((pw & RT_BIT_EXT) && off + 4 <= rt_len) {
        pw = read_u32le(data + off);
        off += 4;
    }
    // off 는 이제 첫 번째 실제 필드의 시작 위치

    // -- bit 0: TSFT (8바이트, 8바이트 정렬) --
    if (main_present & RT_BIT_TSFT) {
        off = (off + 7) & ~static_cast<size_t>(7); // 8바이트 경계
        off += 8;
    }

    // -- bit 1: Flags (1바이트) --
    if (main_present & RT_BIT_FLAGS) {
        if (off >= rt_len) return;
        out.has_fcs = (data[off] & RT_FLAG_FCS) != 0;
        off += 1;
    }

    // -- bit 2: Rate (1바이트) --
    if (main_present & RT_BIT_RATE) {
        off += 1;
    }

    // -- bit 3: Channel (2바이트 정렬, 4바이트) --
    if (main_present & RT_BIT_CHANNEL) {
        off = (off + 1) & ~static_cast<size_t>(1); // 2바이트 경계
        off += 4;
    }

    // -- bit 4: FHSS (2바이트) --
    if (main_present & RT_BIT_FHSS) {
        off += 2;
    }

    // -- bit 5: dBm Antenna Signal (1바이트, signed) --
    if (main_present & RT_BIT_SIGNAL) {
        if (off >= rt_len) return;
        out.power       = static_cast<int8_t>(data[off]);
        out.power_valid = true;
    }
}

// ---------------------------------------------
//  pcap 파일 로딩
// ---------------------------------------------
bool RadioHdr::loadPcap(const std::string& filename) {
    m_packets.clear();

    FILE* fp = fopen(filename.c_str(), "rb");
    if (!fp) return false;

    // 전역 헤더 (24바이트) 읽기
    uint8_t ghdr[24];
    if (fread(ghdr, 1, sizeof(ghdr), fp) != sizeof(ghdr)) {
        fclose(fp);
        return false;
    }

    // magic으로 바이트 오더 판별
    uint32_t magic_raw = read_u32le(ghdr);

    bool little_endian;
    if (magic_raw == PCAP_MAGIC_LE || magic_raw == PCAP_MAGIC_NS_LE) {
        little_endian = true;
    } else if (magic_raw == PCAP_MAGIC_BE || magic_raw == PCAP_MAGIC_NS_BE) {
        little_endian = false;
    } else {
        fclose(fp);
        return false; // 지원하지 않는 포맷
    }

    // 링크 타입 확인 (전역 헤더 [20-23])
    uint32_t linktype = little_endian
                        ? read_u32le(ghdr + 20)
                        : read_u32be(ghdr + 20);

    if (linktype != LINKTYPE_IEEE802_11_RADIOTAP) {
        fclose(fp);
        return false; // RadioTap 링크 타입이 아님
    }

    // 패킷 레코드 순회
    while (true) {
        uint8_t phdr[16];
        if (fread(phdr, 1, sizeof(phdr), fp) != sizeof(phdr)) break;

        uint32_t incl_len = little_endian
                            ? read_u32le(phdr + 8)
                            : read_u32be(phdr + 8);

        // 패킷 데이터 읽기
        std::vector<uint8_t> pkt(incl_len);
        if (fread(pkt.data(), 1, incl_len, fp) != incl_len) break;

        PacketInfo info;
        parseRadiotap(pkt.data(), incl_len, info);
        m_packets.push_back(info);
    }

    fclose(fp);
    return !m_packets.empty();
}

// ---------------------------------------------
//  public 인터페이스
// ---------------------------------------------
int8_t RadioHdr::getPower(int pkt_index) const {
    if (pkt_index < 0 || pkt_index >= static_cast<int>(m_packets.size()))
        return INT8_MIN;
    const PacketInfo& p = m_packets[pkt_index];
    return p.power_valid ? p.power : INT8_MIN;
}

bool RadioHdr::hasFCS(int pkt_index) const {
    if (pkt_index < 0 || pkt_index >= static_cast<int>(m_packets.size()))
        return false;
    return m_packets[pkt_index].has_fcs;
}

int RadioHdr::getPacketCount() const {
    return static_cast<int>(m_packets.size());
}
