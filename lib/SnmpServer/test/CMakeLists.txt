add_executable(SNFSnmpServerTests
    "${CMAKE_CURRENT_SOURCE_DIR}/SnmpMibTreeTests.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/SnmpServerTests.cpp"
)

target_link_libraries(SNFSnmpServerTests
    PRIVATE
        SNFSnmpServer
        GTest::gtest_main
)

target_include_directories(SNFSnmpServerTests
    PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/../src"
)

add_test(NAME SNFSnmpServerTests COMMAND SNFSnmpServerTests)
