cmake_minimum_required(VERSION 3.26)

project(SimplyNodeFramework VERSION 0.1.0 LANGUAGES CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

# ── Platform options ─────────────────────────────────────────────────────────
# SNF_WEB_ASSEMBLY: build SNFCore for WebAssembly/Emscripten.
# The Emscripten toolchain must be active (i.e. run CMake via emcmake or set
# CMAKE_TOOLCHAIN_FILE to the Emscripten.cmake module).
option(SNF_WEB_ASSEMBLY
    "Build SNFCore for WebAssembly/Emscripten (requires the Emscripten toolchain)"
    OFF)
option(SNF_ENABLE_TESTS "Enable tests for SimplyNodeFramework" ${PROJECT_IS_TOP_LEVEL})
option(SNF_ENABLE_EXAMPLES "Build SimplyNodeFramework examples" ${PROJECT_IS_TOP_LEVEL})
option(SNF_ENABLE_WEB_TESTS
    "Enable Node-runnable WebAssembly smoke tests when SNF_WEB_ASSEMBLY is ON"
    ${PROJECT_IS_TOP_LEVEL})
option(SNF_ENABLE_STANDALONE "Build the in-tree standalone examples" ${PROJECT_IS_TOP_LEVEL})
option(SNF_EXPERIMENTAL
    "Build experimental SNF modules such as AsyncTask and AsyncTaskSequence"
    OFF)
option(SNF_ENABLE_SQLITE
    "Enable SQLite support in SNFDatabase"
    ON)
option(SNF_ENABLE_SNMP
    "Build the SNFSnmp module (requires net-snmp / libsnmp-dev)"
    ON)
option(SNF_ENABLE_SNMP_SERVER
    "Build the SNFSnmpServer AgentX subagent module (requires libnetsnmpagent)"
    ON)

# Safety checks: mismatching toolchain / option causes a clear configure error.
if(EMSCRIPTEN AND NOT SNF_WEB_ASSEMBLY)
    message(FATAL_ERROR
        "Emscripten toolchain detected but SNF_WEB_ASSEMBLY is OFF.\n"
        "Pass -DSNF_WEB_ASSEMBLY=ON when configuring with emcmake, "
        "or use a native toolchain.")
endif()

if(SNF_WEB_ASSEMBLY AND NOT EMSCRIPTEN)
    message(FATAL_ERROR
        "SNF_WEB_ASSEMBLY=ON but the Emscripten toolchain is not active.\n"
        "Run CMake through emcmake (or set CMAKE_TOOLCHAIN_FILE), "
        "or set SNF_WEB_ASSEMBLY=OFF for native builds.")
endif()

# Native gtest suites use POSIX sockets, GLFW/OpenGL, and other host APIs.
# Keep those off in WebAssembly mode and use the explicit web smoke tests below.
if(SNF_WEB_ASSEMBLY)
    set(SNF_ENABLE_TESTS OFF CACHE BOOL
        "Native tests disabled automatically in WebAssembly mode" FORCE)
endif()

if(SNF_ENABLE_TESTS OR (SNF_WEB_ASSEMBLY AND SNF_ENABLE_WEB_TESTS))
    include(CTest)
endif()

if (SNF_ENABLE_TESTS)
    include(FetchContent)

    FetchContent_Declare(
        googletest
        URL https://github.com/google/googletest/archive/refs/tags/v1.17.0.zip
    )

    FetchContent_MakeAvailable(googletest)
endif()

# ── Library targets ───────────────────────────────────────────────────────────
add_subdirectory(lib/Core)
add_subdirectory(lib/Json)
add_subdirectory(lib/Database)
add_subdirectory(lib/Network)
if(SNF_EXPERIMENTAL AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/lib/experimental/CMakeLists.txt")
    add_subdirectory(lib/experimental)
endif()

if(NOT SNF_WEB_ASSEMBLY)
    # SNFHttpServer is a development HTTP server; only for native builds.
    add_subdirectory(lib/HttpServer)
    if(SNF_ENABLE_SNMP)
        add_subdirectory(lib/Snmp)
        if(SNF_ENABLE_SNMP_SERVER)
            add_subdirectory(lib/SnmpServer)
        endif()
    endif()
endif()

# SNFWebSocket provides non-TLS ws:// client support on all platforms.
# Its server and manual framing backend are native-only.
add_subdirectory(lib/WebSocket)

# SNFWidgets provides the GLFW+ImGui integration layer.
# On web (SNF_WEB_ASSEMBLY=ON) it uses the Emscripten contrib.glfw3 port and OpenGL ES 3.
# On desktop (SNF_WEB_ASSEMBLY=OFF) it uses system GLFW 3.4+ and OpenGL 3.3 Core Profile.
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/lib/Widgets/CMakeLists.txt")
    add_subdirectory(lib/Widgets)
endif()

if(SNF_ENABLE_STANDALONE AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/standalone/CMakeLists.txt")
    add_subdirectory(standalone)
endif()

if(SNF_ENABLE_EXAMPLES AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/examples/CMakeLists.txt")
    add_subdirectory(examples)
endif()

if(SNF_WEB_ASSEMBLY AND SNF_ENABLE_WEB_TESTS)
    add_executable(SNFWebAssemblySmokeTests
        "${CMAKE_CURRENT_SOURCE_DIR}/test/WebAssemblySmokeTests.cpp"
    )
    target_link_libraries(SNFWebAssemblySmokeTests
        PRIVATE
            SNFCore
            SNFNetwork
            SNFWebSocket
    )
    target_compile_features(SNFWebAssemblySmokeTests PRIVATE cxx_std_17)
    target_link_options(SNFWebAssemblySmokeTests PRIVATE
        -sENVIRONMENT=node
        -sEXIT_RUNTIME=1
        -sFORCE_FILESYSTEM=1
    )
    add_test(NAME SNFWebAssemblySmokeTests COMMAND SNFWebAssemblySmokeTests)
endif()

# ── Package config: SNFCore (always) ─────────────────────────────────────────
configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/SNFCoreConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/SNFCoreConfig.cmake"
    INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/SNFCore"
)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/SNFCoreConfigVersion.cmake"
    VERSION "${PROJECT_VERSION}"
    COMPATIBILITY SameMajorVersion
)

install(
    FILES
        "${CMAKE_CURRENT_BINARY_DIR}/SNFCoreConfig.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/SNFCoreConfigVersion.cmake"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/SNFCore"
)

# ── Package config: SNFNetwork ───────────────────────────────────────────────
    configure_package_config_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/SNFNetworkConfig.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/SNFNetworkConfig.cmake"
        INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/SNFNetwork"
    )

    write_basic_package_version_file(
        "${CMAKE_CURRENT_BINARY_DIR}/SNFNetworkConfigVersion.cmake"
        VERSION "${PROJECT_VERSION}"
        COMPATIBILITY SameMajorVersion
    )

    install(
        FILES
            "${CMAKE_CURRENT_BINARY_DIR}/SNFNetworkConfig.cmake"
            "${CMAKE_CURRENT_BINARY_DIR}/SNFNetworkConfigVersion.cmake"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/SNFNetwork"
    )

# ── Package config: SNFJson ──────────────────────────────────────────────────
    configure_package_config_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/SNFJsonConfig.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/SNFJsonConfig.cmake"
        INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/SNFJson"
    )

    write_basic_package_version_file(
        "${CMAKE_CURRENT_BINARY_DIR}/SNFJsonConfigVersion.cmake"
        VERSION "${PROJECT_VERSION}"
        COMPATIBILITY SameMajorVersion
    )

    install(
        FILES
            "${CMAKE_CURRENT_BINARY_DIR}/SNFJsonConfig.cmake"
            "${CMAKE_CURRENT_BINARY_DIR}/SNFJsonConfigVersion.cmake"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/SNFJson"
    )

# ── Package config: SNFDatabase ─────────────────────────────────────────────
    configure_package_config_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/SNFDatabaseConfig.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/SNFDatabaseConfig.cmake"
        INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/SNFDatabase"
    )

    write_basic_package_version_file(
        "${CMAKE_CURRENT_BINARY_DIR}/SNFDatabaseConfigVersion.cmake"
        VERSION "${PROJECT_VERSION}"
        COMPATIBILITY SameMajorVersion
    )

    install(
        FILES
            "${CMAKE_CURRENT_BINARY_DIR}/SNFDatabaseConfig.cmake"
            "${CMAKE_CURRENT_BINARY_DIR}/SNFDatabaseConfigVersion.cmake"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/SNFDatabase"
    )

if(NOT SNF_WEB_ASSEMBLY)
    # ── Package config: SNFHttpServer (native Linux only) ────────────────────────────
    configure_package_config_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/SNFHttpServerConfig.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/SNFHttpServerConfig.cmake"
        INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/SNFHttpServer"
    )

    write_basic_package_version_file(
        "${CMAKE_CURRENT_BINARY_DIR}/SNFHttpServerConfigVersion.cmake"
        VERSION "${PROJECT_VERSION}"
        COMPATIBILITY SameMajorVersion
    )

    install(
        FILES
            "${CMAKE_CURRENT_BINARY_DIR}/SNFHttpServerConfig.cmake"
            "${CMAKE_CURRENT_BINARY_DIR}/SNFHttpServerConfigVersion.cmake"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/SNFHttpServer"
    )
endif()

# ── Package config: SNFWebSocket ─────────────────────────────────────────────
    configure_package_config_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/SNFWebSocketConfig.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/SNFWebSocketConfig.cmake"
        INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/SNFWebSocket"
    )

    write_basic_package_version_file(
        "${CMAKE_CURRENT_BINARY_DIR}/SNFWebSocketConfigVersion.cmake"
        VERSION "${PROJECT_VERSION}"
        COMPATIBILITY SameMajorVersion
    )

    install(
        FILES
            "${CMAKE_CURRENT_BINARY_DIR}/SNFWebSocketConfig.cmake"
            "${CMAKE_CURRENT_BINARY_DIR}/SNFWebSocketConfigVersion.cmake"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/SNFWebSocket"
    )
