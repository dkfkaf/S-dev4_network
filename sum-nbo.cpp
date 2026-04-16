#include <iostream>
#include <cstdint> 
#include <cstdio>   
#include <arpa/inet.h>  

int main(int argc, char* argv[]) {

    if (argc < 2) {
        return 1;
    }

    uint32_t sum = 0;
    for (int i = 1; i < argc; i++) {
        FILE* fp = fopen(argv[i], "rb");
        if (!fp) {
            std::cerr << "파일 열기 실패" << argv[i] << std::endl;
            return 1;
        }

        uint32_t raw = 0;
        size_t bytesRead = fread(&raw, 1, 4, fp);
        fclose(fp);

        if (bytesRead < 4) {
            std::cerr << "에러 파일 작음" << argv[i] 
                      << bytesRead<< std::endl;
            return 1;
        }

        uint32_t val = ntohl(raw);


        char hexbuf[9];
        snprintf(hexbuf, sizeof(hexbuf), "%08x", val);
        std::cout << val << "(0x" << hexbuf << ")";

        sum += val;
    }

    char hexsum[9];
    snprintf(hexsum, sizeof(hexsum), "%08x", sum);
    std::cout << " = " << sum << "(0x" << hexsum << ")" << std::endl;

    return 0;
}
