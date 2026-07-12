cmake_minimum_required(VERSION 3.20)
project(CapturePlusPlus LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)  # generates compile_commands.json, useful for clangd/editor tooling

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

# --- libpcap ---
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

# --- core library: everything except main(), so tests can link against it too ---
add_library(cappp_core
    packet_capture.cpp
)
target_include_directories(cappp_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(cappp_core PUBLIC ${PCAP_INCLUDE_DIRS})
target_link_libraries(cappp_core PUBLIC ${PCAP_LIBRARIES})
target_compile_options(cappp_core PUBLIC ${PCAP_CFLAGS_OTHER})

# --- the actual binary ---
add_executable(cappp main.cpp)
target_link_libraries(cappp PRIVATE cappp_core)

# --- tests ---
enable_testing()
option(BUILD_TESTS "Build unit tests" ON)
if(BUILD_TESTS)
    add_subdirectory(tests)
endif()
