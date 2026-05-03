#pragma once

#include "pch.h"

struct Mac {
    uint8_t mac_[6];

    Mac() { memset(mac_, 0, 6); }
    Mac(const char* s);
    Mac(const std::string& s);
    Mac(const Mac& r);

    std::string toString() const;
    operator std::string() const { return toString(); }

    static Mac fromString(const std::string& s);

    bool operator==(const Mac& r) const { return memcmp(mac_, r.mac_, 6) == 0; }
    bool operator<(const Mac& r)  const { return memcmp(mac_, r.mac_, 6) <  0; }
};

// 802.11 packet structures (#pragma pack required)
#pragma pack(push, 1)

struct dot11RadioTap {
    uint8_t  it_version;
    uint8_t  it_pad;
    uint16_t it_len;
    uint32_t it_present;
};

struct dot11MacHdr {
    uint16_t frameControl;
    uint16_t duration;
    Mac      addr1;   // Destination
    Mac      addr2;   // Source
    Mac      addr3;   // BSSID (beacon 기준)
    uint16_t seqCtrl;
};

struct dot11Beacon {
    uint64_t timestamp;
    uint16_t beaconInterval;
    uint16_t capabilityInfo;
};

struct TaggedParam {
    uint8_t tag;
    uint8_t len;
    uint8_t data[0];
};
typedef TaggedParam* PTaggedParam;

#pragma pack(pop)

struct APInfo {
    std::string bssid;
    std::string essid;
    int    beacons = 0;
    int8_t pwr     = 0;
};

struct StaInfo {
    std::string station;
    std::string bssid;
    int packets = 0;
};
