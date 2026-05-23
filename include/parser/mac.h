#pragma once
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>
#include <string>

struct Mac {
    uint8_t mac_[6];

    Mac() { std::memset(mac_, 0, 6); }

    // "aa:bb:cc:dd:ee:ff" 형식 문자열을 파싱한다. 형식이 잘못되면 nullopt.
    static std::optional<Mac> fromString(const std::string& s) {
        unsigned int v[6];
        char extra;
        int n = std::sscanf(s.data(), "%x:%x:%x:%x:%x:%x%c",
                            &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &extra);
        if (n != 6) return std::nullopt;

        Mac m;
        for (int i = 0; i < 6; ++i) {
            if (v[i] > 0xFF) return std::nullopt;
            m.mac_[i] = static_cast<uint8_t>(v[i]);
        }
        return m;
    }

    Mac& operator=(const Mac&) = default;

    bool operator==(const Mac& r) const { return std::memcmp(mac_, r.mac_, sizeof(mac_)) == 0; }
    bool operator!=(const Mac& r) const { return !(*this == r); }
    bool operator< (const Mac& r) const { return std::memcmp(mac_, r.mac_, sizeof(mac_)) <  0; }
    bool operator> (const Mac& r) const { return r < *this; }
    bool operator<=(const Mac& r) const { return !(r < *this); }
    bool operator>=(const Mac& r) const { return !(*this < r); }

    std::string toString() const {
        char buf[18];
        std::snprintf(buf, sizeof(buf),
                      "%02X:%02X:%02X:%02X:%02X:%02X",
                      mac_[0], mac_[1], mac_[2],
                      mac_[3], mac_[4], mac_[5]);
        return buf;
    }
};
