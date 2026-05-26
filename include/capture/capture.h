#pragma once
#include <atomic>
#include <memory>
#include <vector>
#include <pcap.h>
#include "i_detector.h"

/* pcap 핸들과 capture 루프 — main.cpp에서 분리.
   open_monitor: 한 인터페이스를 monitor mode + radiotap + deauth BPF 필터로 연다.
   capture_loop: 한 pcap에서 frame을 받아 모든 디텍터에 broadcast. */

pcap_t* open_monitor(const char* ifname);

void capture_loop(pcap_t* pcap, const char* label,
                  std::vector<std::unique_ptr<IDetector>>& detectors,
                  const std::atomic<bool>& running);
