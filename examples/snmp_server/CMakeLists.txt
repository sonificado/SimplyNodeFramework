cmake_minimum_required(VERSION 3.26)

if(NOT TARGET SNFSnmpServer)
    message(STATUS "Skipping snmp_server example — SNFSnmpServer not available")
    return()
endif()

add_executable(snmp_server main.cpp)

target_link_libraries(snmp_server
    PRIVATE
        SNFCore
        SNFSnmp
        SNFSnmpServer
)

target_compile_options(snmp_server PRIVATE -Wall -Wextra)

# Copy the MIB definition file next to the binary so the example can find it
# with a relative path regardless of the working directory.
add_custom_command(TARGET snmp_server POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_CURRENT_SOURCE_DIR}/my-device.mib"
        "$<TARGET_FILE_DIR:snmp_server>/my-device.mib"
    COMMENT "Copying my-device.mib to build directory"
)
