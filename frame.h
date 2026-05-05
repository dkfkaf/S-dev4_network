#pragma once
#include <cstdint>
#include <cstddef>
#include "mac.h"

size_t build_frame(uint8_t* buf,
                   const Mac& da,
                   const Mac& sa,
                   const Mac& bssid,
                   uint16_t seq);
