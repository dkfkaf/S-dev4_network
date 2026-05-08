# =============================================================================
# csa-attack CMake build script
# -----------------------------------------------------------------------------
# 빌드 방법 (Linux):
#   $ cmake -B build                     # Release 빌드 설정 (기본)
#   $ cmake -B build -DCMAKE_BUILD_TYPE=Debug   # Debug 빌드 설정
#   $ cmake --build build                # 실제 빌드
#   $ ./build/csa-attack <interface> <ap mac> [<station mac>]
# =============================================================================
cmake_minimum_required(VERSION 3.10)

project(csa-attack
    VERSION  1.0
    LANGUAGES CXX
)

# ---- C++ 표준 ----
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ---- 기본 빌드 타입 (지정 안 하면 Release) ----
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# ---- libpcap 찾기 ----
find_path(PCAP_INCLUDE_DIR
    NAMES pcap.h
    PATH_SUFFIXES pcap
)
find_library(PCAP_LIBRARY
    NAMES pcap
)

if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
    message(FATAL_ERROR
        "libpcap not found.\n"
        "  Ubuntu/Debian : sudo apt install libpcap-dev\n"
        "  Fedora/RHEL   : sudo dnf install libpcap-devel\n"
        "  Arch          : sudo pacman -S libpcap"
    )
endif()

message(STATUS "PCAP include : ${PCAP_INCLUDE_DIR}")
message(STATUS "PCAP library : ${PCAP_LIBRARY}")

# ---- 실행 파일 정의 ----
add_executable(csa-attack
    main.cpp
    frame.cpp
)

target_include_directories(csa-attack PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${PCAP_INCLUDE_DIR}
)

target_link_libraries(csa-attack PRIVATE
    ${PCAP_LIBRARY}
)

# ---- 컴파일 경고 옵션 ----
target_compile_options(csa-attack PRIVATE
    -Wall
    -Wextra
)
