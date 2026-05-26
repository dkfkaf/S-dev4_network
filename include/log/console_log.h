#pragma once
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <type_traits>
#include <variant>

#include "alert.h"
#include "mgmt_parser.h"

// 헤더 전역 변수 회피 — function-local static으로 같은 효과 (C++17 magic statics가 thread-safe init 보장).
inline std::mutex& outputMutex() { static std::mutex m; return m; }

inline void print_frame(const char* label, const ParsedFrame& f) {
    std::lock_guard<std::mutex> lock(outputMutex());
    if (label) std::cout << "[" << label << "]";
    std::cout
        << "[" << toString(f.frameType) << "]"
        << "  src="   << f.src.toString()
        << "  dst="   << f.dst.toString()
        << "  bssid=" << f.bssid.toString();
    if (f.ssid.has_value()) {
        if (f.ssid.value().empty()) std::cout << "  ssid=<hidden>";
        else                        std::cout << "  ssid=\"" << f.ssid.value() << "\"";
    }
    if (f.rssi.has_value())
        std::cout << "  rssi=" << static_cast<int>(f.rssi.value()) << "dBm";
    if (f.channel.has_value())
        std::cout << "  ch=" << f.channel.value();
    if (f.reasonCode.has_value())
        std::cout << "  reason=" << f.reasonCode.value();
    std::cout << "\n";
}

inline std::string format_deauth_flood(const Alert& a, const DeauthFloodPayload& p) {
    std::ostringstream oss;
    switch (p.scope) {
        case AlertScope::globalRate:
            oss << "global deauth flood: " << p.count
                << " events in last " << p.window.count() << "ms";
            if (a.channel.has_value()) oss << " (latest: ch=" << a.channel.value() << ")";
            break;
        case AlertScope::perSrcMac:
            // srcMac 없으면 producer 측 invariant 위반 — 메시지로 알리고 throw 회피
            if (!p.srcMac.has_value()) { oss << "(perSrcMac alert without srcMac payload)"; break; }
            oss << "deauth from srcMac=" << p.srcMac.value().toString()
                << ": " << p.count << " events in last " << p.window.count() << "ms"
                << " (total=" << p.total;
            if (a.channel.has_value())    oss << ", ch=" << a.channel.value();
            if (p.bssid.has_value())      oss << ", target=" << p.bssid.value().toString();
            if (p.rssi.has_value())       oss << ", rssi=" << static_cast<int>(p.rssi.value()) << "dBm";
            if (p.reasonCode.has_value()) oss << ", reason=" << p.reasonCode.value();
            oss << ")";
            break;
        case AlertScope::perBssid:
            if (!p.bssid.has_value()) { oss << "(perBssid alert without bssid payload)"; break; }
            oss << "deauth targeting " << p.bssid.value().toString()
                << ": " << p.count << " events in last " << p.window.count() << "ms"
                << " (total=" << p.total;
            if (a.channel.has_value())    oss << ", ch=" << a.channel.value();
            if (p.rssi.has_value())       oss << ", rssi=" << static_cast<int>(p.rssi.value()) << "dBm";
            if (p.reasonCode.has_value()) oss << ", latest_reason=" << p.reasonCode.value();
            oss << ")";
            break;
    }
    return oss.str();
}

/*애는 모르겠는데*/
inline std::string format_alert(const Alert& a) {
    return std::visit([&](const auto& payload) -> std::string {
        using T = std::decay_t<decltype(payload)>;
        if constexpr (std::is_same_v<T, DeauthFloodPayload>) {
            return format_deauth_flood(a, payload);
        } else {
            return "[unknown alert payload]";
        }
    }, a.payload);
}

inline void print_alert(const Alert& a) {
    std::lock_guard<std::mutex> lock(outputMutex());
    std::cout << "[ALERT " << categoryName(a.payload)
              << " "       << toString(a.severity)
              << "] "      << format_alert(a) << "\n";
}
