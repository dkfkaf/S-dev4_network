#pragma once
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <type_traits>
#include <variant>

#include "alert.h"
#include "mgmt_parser.h"

inline std::mutex g_outputMtx;

inline void print_frame(const char* label, const ParsedFrame& f) {
    std::lock_guard<std::mutex> lock(g_outputMtx);
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
    if (p.scope == AlertScope::global) {
        oss << "global deauth flood: " << p.count
            << " events in last " << p.window.count() << "ms";
        if (a.channel.has_value()) oss << " (latest: ch=" << a.channel.value() << ")";
    } else {
        oss << "deauth from " << p.source.value().toString()
            << ": " << p.count << " events in last " << p.window.count() << "ms"
            << " (total=" << p.total;
        if (a.channel.has_value())    oss << ", latest: ch=" << a.channel.value();
        if (p.reasonCode.has_value()) oss << ", reason=" << p.reasonCode.value();
        oss << ")";
    }
    return oss.str();
}

/* 새 payload 추가 시 if constexpr 분기 하나만 늘리면 됨.
   누락 시 컴파일 에러로 잡힘 (정적 type 매칭) — runtime "unknown category"보다 안전. */
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
    std::lock_guard<std::mutex> lock(g_outputMtx);
    std::cout << "[ALERT " << categoryName(a.payload)
              << " "       << toString(a.severity)
              << "] "      << format_alert(a) << "\n";
}
