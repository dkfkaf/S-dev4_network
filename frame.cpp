#include "frame.h"
#include "dot11.h"
#include <cstring>

size_t build_frame(uint8_t* buf,
                   const Mac& da,
                   const Mac& sa,
                   const Mac& bssid,
                   uint16_t seq)
{
    size_t offset = 0;

    dot11RadioTap* rt = reinterpret_cast<dot11RadioTap*>(buf);
    rt->it_version = 0;
    rt->it_pad     = 0;
    rt->it_len     = sizeof(dot11RadioTap);
    rt->it_present = 0;
    offset += sizeof(dot11RadioTap);

    dot11MacHdr* hdr = reinterpret_cast<dot11MacHdr*>(buf + offset);
    hdr->frameControl = dot11MacHdr::FC_DEAUTH;
    hdr->duration     = 0x013A;
    hdr->addr1        = da;
    hdr->addr2        = sa;
    hdr->addr3        = bssid;
    hdr->seqCtrl      = static_cast<uint16_t>((seq & 0x0FFF) << 4);
    offset += sizeof(dot11MacHdr);

    uint16_t reason = 0x0007;
    std::memcpy(buf + offset, &reason, 2); offset += 2;

    return offset;
}
