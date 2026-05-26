cmake_minimum_required(VERSION 3.16)

project(wips-parser
    VERSION  1.0
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

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

find_package(glog QUIET)
if(NOT glog_FOUND)
    message(FATAL_ERROR
        "google-glog not found.\n"
        "  Ubuntu/Debian : sudo apt install libgoogle-glog-dev\n"
        "  Fedora/RHEL   : sudo dnf install glog-devel\n"
        "  Arch          : sudo pacman -S google-glog"
    )
endif()

message(STATUS "PCAP include : ${PCAP_INCLUDE_DIR}")
message(STATUS "PCAP library : ${PCAP_LIBRARY}")

add_executable(wips-parser
    src/main.cpp
    src/parser/parser.cpp
    src/detector/deauth_detector.cpp
    src/hopper/channel_hopper.cpp
    src/capture/capture.cpp
    src/runtime/startup.cpp
)

find_package(Threads REQUIRED)

target_precompile_headers(wips-parser PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include/pch.h
)

target_include_directories(wips-parser PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/include/parser
    ${CMAKE_CURRENT_SOURCE_DIR}/include/detector
    ${CMAKE_CURRENT_SOURCE_DIR}/include/hopper
    ${CMAKE_CURRENT_SOURCE_DIR}/include/log
    ${CMAKE_CURRENT_SOURCE_DIR}/include/capture
    ${CMAKE_CURRENT_SOURCE_DIR}/include/runtime
    ${PCAP_INCLUDE_DIR}
)

target_link_libraries(wips-parser PRIVATE
    ${PCAP_LIBRARY}
    Threads::Threads
    glog::glog
)

target_compile_options(wips-parser PRIVATE
    -Wall
    -Wextra
)

# ── Tests ────────────────────────────────────────────────────────────────────
# GoogleTest가 설치돼 있으면 wips-tests 타겟 추가. 없으면 그냥 skip — 빌드 안 깨짐.
#   Ubuntu/Debian : sudo apt install libgtest-dev
#   Fedora/RHEL   : sudo dnf install gtest-devel
#   Arch          : sudo pacman -S gtest
# 실행: cd build && ctest --output-on-failure
find_package(GTest QUIET)
if(GTest_FOUND)
    enable_testing()

    add_executable(wips-tests
        tests/test_deauth_detector.cpp
        src/detector/deauth_detector.cpp
    )

    target_include_directories(wips-tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/include/parser
        ${CMAKE_CURRENT_SOURCE_DIR}/include/detector
        ${CMAKE_CURRENT_SOURCE_DIR}/include/log
        ${PCAP_INCLUDE_DIR}
    )

    # pch.h가 <pcap.h>, <glog/logging.h>를 포함하므로 둘 다 링크 필요
    target_link_libraries(wips-tests PRIVATE
        ${PCAP_LIBRARY}
        Threads::Threads
        glog::glog
        GTest::gtest
        GTest::gtest_main
    )

    target_compile_options(wips-tests PRIVATE -Wall -Wextra)

    include(GoogleTest)
    gtest_discover_tests(wips-tests)
else()
    message(STATUS "GoogleTest not found — wips-tests 타겟 비활성. 설치 후 cmake 재실행하면 활성화됨.")
endif()
