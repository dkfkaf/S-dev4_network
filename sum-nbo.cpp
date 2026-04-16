#include <iostream>
#include <cstdint> 
#include <cstdio>   
#include <arpa/inet.h>  

int main(int argc, char* argv[]) {
    // 인자가 하나도 없으면 사용법 출력 후 종료
    if (argc < 2) {
        return 1;
    }

    uint32_t sum = 0;   // 모든 파일에서 읽은 숫자들의 합

    // 커맨드라인 인자로 받은 파일들을 순서대로 처리
    for (int i = 1; i < argc; i++) {

        // 파일을 바이너리 읽기 모드("rb")로 열기
        FILE* fp = fopen(argv[i], "rb");
        if (!fp) {
            // 파일 열기 실패 시 에러 출력 후 종료
            std::cerr << "파일 열기 실패" << argv[i] << std::endl;
            return 1;
        }

        uint32_t raw = 0;
        // 파일에서 4바이트를 읽어 raw에 저장 (network byte order 그대로)
        size_t bytesRead = fread(&raw, 1, 4, fp);
        fclose(fp);  // 파일 사용 후 즉시 닫기

        // 4바이트 미만으로 읽혔다면 파일이 너무 작은 것 → 에러 처리
        if (bytesRead < 4) {
            std::cerr << "에러 파일 작음" << argv[i] 
                      << bytesRead<< std::endl;
            return 1;
        }

        // ntohl: network byte order(big-endian) → host byte order로 변환
        // x86/x64(little-endian)에서는 바이트 순서를 뒤집어 줌
        uint32_t val = ntohl(raw);


        // 값을 "1000(0x000003e8)" 형식으로 출력
        char hexbuf[9];
        snprintf(hexbuf, sizeof(hexbuf), "%08x", val);  // 8자리 16진수로 포맷
        std::cout << val << "(0x" << hexbuf << ")";

        // 합산 (overflow는 과제 명세에 따라 무시)
        sum += val;
    }

    // 최종 합계를 " = 1700(0x000006a4)" 형식으로 출력
    char hexsum[9];
    snprintf(hexsum, sizeof(hexsum), "%08x", sum);
    std::cout << " = " << sum << "(0x" << hexsum << ")" << std::endl;

    return 0;
}