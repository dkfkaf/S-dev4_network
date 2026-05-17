#pragma once
#include <cstdint>
#include <vector>
#include "mac.h"

// 성공 시 완성된 CSA beacon 프레임을 반환한다. 실패 시 빈 vector.
std::vector<uint8_t> build_csa_beacon(
    const std::vector<uint8_t>& captured,
    bool                        useUnicast,
    const Mac&                  staMac
);
