cmake_minimum_required(VERSION 3.26)

if(NOT TARGET SNFSnmp)
    message(STATUS "Skipping snmp_server_client example — SNFSnmp not available")
    return()
endif()

add_executable(snmp_server_client main.cpp)

target_link_libraries(snmp_server_client
    PRIVATE
        SNFCore
        SNFSnmp
)

target_compile_options(snmp_server_client PRIVATE -Wall -Wextra)
