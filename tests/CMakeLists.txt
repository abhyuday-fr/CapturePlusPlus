find_package(GTest REQUIRED)

add_executable(cappp_tests
    test_packet_capture.cpp
    test_protocols.cpp
    test_packet_queue.cpp
)
target_link_libraries(cappp_tests PRIVATE cappp_core GTest::gtest GTest::gtest_main)
target_compile_definitions(cappp_tests PRIVATE
    FIXTURES_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures"
)

include(GoogleTest)
gtest_discover_tests(cappp_tests)
