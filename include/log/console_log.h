#pragma once
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>

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

inline std::string format_alert(const Alert& a) {
    std::ostringstream oss;
    if (a.scope == AlertScope::global) {
        oss << "global deauth flood: " << a.count
            << " events in last " << a.window.count() << "ms";
        if (a.channel.has_value()) oss << " (latest: ch=" << a.channel.value() << ")";
    } else {
        oss << "deauth from " << a.source.value().toString()
            << ": " << a.count << " events in last " << a.window.count() << "ms"
            << " (total=" << a.total;
        if (a.channel.has_value())    oss << ", latest: ch=" << a.channel.value();
        if (a.reasonCode.has_value()) oss << ", reason=" << a.reasonCode.value();
        oss << ")";
    }
    return oss.str();
}

inline void print_alert(const Alert& a) {
    std::lock_guard<std::mutex> lock(g_outputMtx);
    std::cout << "[ALERT " << toString(a.severity) << "] " << format_alert(a) << "\n";
}
