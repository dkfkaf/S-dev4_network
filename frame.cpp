#include "pch.h"
#include "frame.h"
#include "dot11.h"
#include "tag.h"

static constexpr size_t BEACON_FIXED_LEN = sizeof(Dot11) + sizeof(Beacon);

struct BeaconLayout {
    size_t rtLen;
    size_t dot11End;
    size_t tagsLen;
};

static bool check_layout(const std::vector<uint8_t>& cap, BeaconLayout& layout) {
    if (cap.size() < sizeof(Dot11RadioTap)) return false;

    Dot11RadioTap rt; std::memcpy(&rt, cap.data(), sizeof(rt));

    layout.rtLen = rt.len();
    if (layout.rtLen < sizeof(Dot11RadioTap) || layout.rtLen > cap.size()) return false;

    layout.dot11End = rt.hasFCS_dataEnd(cap.data(), cap.size());
    if (layout.dot11End < layout.rtLen + BEACON_FIXED_LEN) return false;

    layout.tagsLen = layout.dot11End - layout.rtLen - BEACON_FIXED_LEN;
    return true;
}

// 캡처한 Beacon을 기반으로 CSA/ECSA 태그를 삽입한 송신용 프레임을 반환한다.
// useUnicast=true이면 addr1을 staMac으로 교체해 유니캐스트로 송신한다.
std::vector<uint8_t> build_csa_beacon(
    const std::vector<uint8_t>& captured,
    bool                        useUnicast,
    const Mac&                  staMac)
{
    BeaconLayout layout;
    if (!check_layout(captured, layout)) return {};

    const uint8_t* dot11Start = captured.data() + layout.rtLen;

    // 원본 CSA/ECSA는 제거 후 항상 새 태그 두 개로 교체되므로 둘 다 확보
    const size_t csaTagsSize = sizeof(Beacon::CsaTag) + sizeof(Beacon::EcsaTag);

    std::vector<uint8_t> out;
    out.reserve(sizeof(Dot11RadioTap) + (layout.dot11End - layout.rtLen) + csaTagsSize);  // 메모리만 미리 확보 (size는 0 유지)

    // 새 Radiotap 헤더 + 원본 Dot11/Beacon 고정 파라미터 복사
    const Dot11RadioTap txRt{};
    append_tag(out, &txRt, sizeof(txRt));
    out.insert(out.end(), dot11Start, dot11Start + BEACON_FIXED_LEN);

    // 유니캐스트 시 수신 MAC(addr1)을 STA 주소로 교체
    if (useUnicast) {
        Dot11 dot11hdr;
        std::memcpy(&dot11hdr, out.data() + sizeof(Dot11RadioTap), sizeof(Dot11));
        dot11hdr.setDst(staMac);
        std::memcpy(out.data() + sizeof(Dot11RadioTap), &dot11hdr, sizeof(Dot11));
    }

    // 기존 태그 정렬을 유지하며 CSA/ECSA 삽입
    insert_tag_in_capture(out, dot11Start + BEACON_FIXED_LEN, layout.tagsLen,
                       Beacon::CsaTag{}, Beacon::EcsaTag{});
    return out;
}
