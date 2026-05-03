#include "frame.h"
#include "dot11.h"
#include <cstring>

size_t build_frame(uint8_t* buf,
                   const Mac& da,
                   const Mac& sa,
                   const Mac& bssid,
                   bool isAuth,
                   uint16_t seq)
{
    size_t offset = 0; // 현재까지 버퍼에 쓴 바이트 수 (= 다음 쓸 위치)

    // ── 1단계: Radiotap 헤더 8바이트 작성 ──────────────────
    // reinterpret_cast<T*>: 포인터 타입을 강제 변환
    // 쓰는 이유: 메모리는 그대로, 타입만 바꿔서 구조체 멤버 이름으로 접근하려고 쓰는 것.
    // buf의 시작 주소를 dot11RadioTap 구조체 포인터로 해석 → 멤버 접근 가능
    dot11RadioTap* rt = reinterpret_cast<dot11RadioTap*>(buf);
    rt->it_version = 0;                           // 버전: 항상 0
    rt->it_pad     = 0;                           // 패딩: 항상 0
    rt->it_len     = sizeof(dot11RadioTap);       // 헤더 길이 8로 저장
    rt->it_present = 0;                           // 추가 필드 없음 (present flags = 0)
    offset += sizeof(dot11RadioTap);              // offset을 8 증가 (802.11 mac구조체 위치로 이동시키기 위해서)

    // ── 2단계: 802.11 MAC 헤더 24바이트 작성 ────────────────
    // buf + offset: radiotap 다음 위치를 dot11MacHdr 구조체로 해석
    dot11MacHdr* hdr = reinterpret_cast<dot11MacHdr*>(buf + offset);

    // frameControl: isAuth가 true면 FC_AUTH(0x00B0), false면 FC_DEAUTH(0x00C0)
    if (isAuth) {
        hdr->frameControl = dot11MacHdr::FC_AUTH;
    } else {
        hdr->frameControl = dot11MacHdr::FC_DEAUTH;
    }

    hdr->duration = 0x013A; // 전송 지속 시간: 0x013A = 314 마이크로초
    hdr->addr1    = da;     // 목적지 MAC (DA): 함수 파라미터로 받은 값
    hdr->addr2    = sa;     // 출발지 MAC (SA): 실제로는 위조된 주소
    hdr->addr3    = bssid;  // BSSID: AP의 MAC 주소

    // seqCtrl(Sequence Control) 필드 계산:
    //   상위 12비트 = 시퀀스 번호, 하위 4비트 = 단편 번호(항상 0)
    //   (seq & 0x0FFF): seq를 12비트로 마스킹 (0x0FFF = 0000 1111 1111 1111)
    //   << 4: 12비트 값을 4칸 왼쪽으로 시프트 → 상위 12비트 자리로 이동
    hdr->seqCtrl = static_cast<uint16_t>((seq & 0x0FFF) << 4);
    offset += sizeof(dot11MacHdr); // offset을 24 증가 ==reason code 부분으로 넘어가기 위해 넣어둠

    
    //deauthentication frame body (2바이트):
    //Authentication frame body (6바이트)
    //reason code== frame body

    // ── 3단계: Frame Body 작성 ──────────────────────────────
    if (isAuth) {
        // Authentication frame body (6바이트):
        //   알고리즘 번호(2B) + 인증 시퀀스 번호(2B) + 상태 코드(2B)
        uint16_t alg    = 0x0000; // 인증 알고리즘: 0 = Open System (개방형 인증)
        uint16_t seqnum = 0x0001; // 인증 시퀀스: 1 = 첫 번째 인증 요청
        uint16_t status = 0x0000; // 상태 코드: 0 = Successful (성공)

        // memcpy: &alg가 가리키는 주소에서 2바이트를 buf+offset 위치에 복사
        std::memcpy(buf + offset, &alg,    2); offset += 2;
        std::memcpy(buf + offset, &seqnum, 2); offset += 2;
        std::memcpy(buf + offset, &status, 2); offset += 2;
        // Auth 패킷 총 크기: 8 + 24 + 6 = 40 바이트
    } else {
        // Deauthentication frame body (2바이트):
        //   이유 코드(Reason Code) 2바이트만 존재
        uint16_t reason = 0x0007; // Reason Code 7: 비연결 STA로부터 Class 3 프레임 수신
        std::memcpy(buf + offset, &reason, 2); offset += 2;
        // Deauth 패킷 총 크기: 8 + 24 + 2 = 34 바이트
    }

    return offset; // 완성된 패킷의 총 바이트 수를 반환
}
