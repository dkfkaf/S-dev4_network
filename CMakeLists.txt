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
