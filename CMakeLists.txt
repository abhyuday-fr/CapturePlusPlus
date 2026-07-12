cmake_minimum_required(VERSION 3.20)
project(CapturePlusPlus LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)
find_package(Threads REQUIRED)
find_package(ftxui REQUIRED)

# --- backend: capture + protocol dissection, zero UI dependencies ---
add_library(cappp_core
    src/capture/packet_capture.cpp
    src/capture/packet_queue.cpp
)
target_include_directories(cappp_core PUBLIC src ${PCAP_INCLUDE_DIRS})
target_link_libraries(cappp_core PUBLIC ${PCAP_LIBRARIES} Threads::Threads)
target_compile_options(cappp_core PUBLIC ${PCAP_CFLAGS_OTHER})

# --- UI layer: depends on core, adds FTXUI ---
add_library(cappp_ui
    src/ui/app.cpp
)
target_link_libraries(cappp_ui PUBLIC
    cappp_core
    ftxui::component
    ftxui::dom
    ftxui::screen
)

# --- the actual binary ---
add_executable(cappp main.cpp)
target_link_libraries(cappp PRIVATE cappp_ui)

enable_testing()
option(BUILD_TESTS "Build unit tests" ON)
if(BUILD_TESTS)
    add_subdirectory(tests)
endif()
