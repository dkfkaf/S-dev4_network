#pragma once
#include <cstdint>
#include <cstddef>
#include "mac.h"

size_t build_csa_beacon(uint8_t* outBuf, size_t outBufSize,
                        const uint8_t* captured, size_t capturedLen,
                        bool useUnicast, const Mac& staMac);
