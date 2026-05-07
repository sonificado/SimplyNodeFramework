cmake_minimum_required(VERSION 3.26)

set(SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src")

# ── Locate net-snmp base library (re-use SNFSnmp's detection logic) ───────────
# By the time we get here, SNFSnmp has already found libnetsnmp and its
# include dirs are available; we inherit them via the SNFSnmp link dependency.

# ── Locate libnetsnmpagent (separate from the manager/client library) ─────────
find_package(PkgConfig QUIET)

if(PkgConfig_FOUND)
    pkg_check_modules(NETSNMP_AGENT QUIET netsnmp-agent)
endif()

if(NOT NETSNMP_AGENT_FOUND)
    find_library(NETSNMP_AGENT_LIB_PATH NAMES netsnmpagent)
    find_path(NETSNMP_AGENT_INCLUDE_PATH
        NAMES net-snmp/agent/net-snmp-agent-includes.h)

    if(NETSNMP_AGENT_LIB_PATH AND NETSNMP_AGENT_INCLUDE_PATH)
        set(NETSNMP_AGENT_FOUND TRUE)
        set(NETSNMP_AGENT_LIBRARIES     "${NETSNMP_AGENT_LIB_PATH}")
        set(NETSNMP_AGENT_INCLUDE_DIRS  "${NETSNMP_AGENT_INCLUDE_PATH}")
        set(NETSNMP_AGENT_LINK_LIBRARIES "${NETSNMP_AGENT_LIB_PATH}")
    endif()
endif()

if(NOT NETSNMP_AGENT_FOUND)
    message(WARNING
        "libnetsnmpagent not found — SNFSnmpServer target will not be built.\n"
        "Install net-snmp agent libraries (e.g. 'sudo apt install libsnmp-dev') "
        "and re-configure.")
    return()
endif()

# ── Sources ───────────────────────────────────────────────────────────────────
add_subdirectory("${SRC_DIR}")

# ── Library target ────────────────────────────────────────────────────────────
add_library(SNFSnmpServer STATIC)

target_sources(SNFSnmpServer
    PRIVATE
        ${SNFSNMPSERVER_SOURCES}
    PUBLIC
        FILE_SET HEADERS
        BASE_DIRS "${SRC_DIR}"
        FILES
            ${SNFSNMPSERVER_HEADERS}
)

target_link_libraries(SNFSnmpServer
    PUBLIC
        SNFSnmp
    PRIVATE
        ${NETSNMP_AGENT_LINK_LIBRARIES}
)

target_include_directories(SNFSnmpServer
    PUBLIC
        $<BUILD_INTERFACE:${SRC_DIR}>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE
        ${NETSNMP_AGENT_INCLUDE_DIRS}
)

target_compile_features(SNFSnmpServer PUBLIC cxx_std_17)

add_library(SNFSnmpServer::SNFSnmpServer ALIAS SNFSnmpServer)

# ── Install ───────────────────────────────────────────────────────────────────
install(TARGETS SNFSnmpServer
    EXPORT SNFSnmpServerTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    FILE_SET HEADERS DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(
    EXPORT SNFSnmpServerTargets
    FILE SNFSnmpServerTargets.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/SNFSnmpServer
)

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/SNFSnmpServerConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/SNFSnmpServerConfig.cmake"
    INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/SNFSnmpServer"
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/SNFSnmpServerConfig.cmake"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/SNFSnmpServer"
)

# ── Tests ─────────────────────────────────────────────────────────────────────
if(SNF_ENABLE_TESTS)
    add_subdirectory(test)
endif()
