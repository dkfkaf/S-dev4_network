#pragma once
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <stdexcept>

struct Mac {
    uint8_t mac_[6];

    Mac() { std::memset(mac_, 0, 6); }

    explicit Mac(const std::string& s) {
        unsigned int v[6];
        char extra;
        int n = std::sscanf(s.data(), "%x:%x:%x:%x:%x:%x%c",
                            &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &extra);
        if (n != 6) {
            throw std::invalid_argument("invalid MAC: " + s);
        }
        for (int i = 0; i < 6; ++i) {
            if (v[i] > 0xFF) {
                throw std::invalid_argument("invalid MAC: " + s);
            }
            mac_[i] = static_cast<uint8_t>(v[i]);
        }
    }

    std::string toString() const {
        char buf[18];
        std::snprintf(buf, sizeof(buf),
                      "%02X:%02X:%02X:%02X:%02X:%02X",
                      mac_[0], mac_[1], mac_[2],
                      mac_[3], mac_[4], mac_[5]);
        return buf;
    }
};
