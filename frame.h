#pragma once
#include <cstdint>
#include <cstddef>
#include "mac.h"

size_t build_csa_beacon(
    uint8_t*       out_Buf,
    size_t         in_BufSize,
    const uint8_t* in_captured,
    size_t         in_capturedLen,
    bool           in_useUnicast,
    const Mac&     in_staMac
);
