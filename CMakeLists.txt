cmake_minimum_required(VERSION 3.28)

project(kasumi VERSION 0.5.1 LANGUAGES C CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

include(CTest)

option(
    KASUMI_BUILD_SYSTEM_TESTS
    "Build Kasumi system tests that require external executables"
    OFF
)
option(
    KASUMI_BUILD_BENCHMARKS
    "Build Kasumi operational benchmark executables"
    OFF
)

add_library(kasumi_warnings INTERFACE)
if(WIN32)
    add_compile_definitions(NOMINMAX _CRT_SECURE_NO_WARNINGS)
    if(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
        add_compile_options(/bigobj)
    endif()
endif()
if(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    target_compile_options(kasumi_warnings INTERFACE
        $<$<COMPILE_LANGUAGE:CXX>:/W4>
        $<$<COMPILE_LANGUAGE:CXX>:/permissive->
        $<$<COMPILE_LANGUAGE:CXX>:/utf-8>
    )
else()
    target_compile_options(kasumi_warnings INTERFACE
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wsign-conversion
        -Wshadow
        -Wno-missing-field-initializers
    )
endif()

add_library(kasumi_release_optimizations INTERFACE)
if(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    target_compile_options(kasumi_release_optimizations INTERFACE
        $<$<OR:$<CONFIG:Release>,$<CONFIG:MinSizeRel>>:/O2 /Gy /Gw>
    )
    target_link_options(kasumi_release_optimizations INTERFACE
        $<$<OR:$<CONFIG:Release>,$<CONFIG:MinSizeRel>>:/OPT:REF /OPT:ICF>
    )
else()
    target_compile_options(kasumi_release_optimizations INTERFACE
        $<$<OR:$<CONFIG:Release>,$<CONFIG:MinSizeRel>>:-O2 -ffunction-sections -fdata-sections>
    )
    target_link_options(kasumi_release_optimizations INTERFACE
        $<$<OR:$<CONFIG:Release>,$<CONFIG:MinSizeRel>>:-Wl,--gc-sections -s>
    )
endif()

add_library(kasumi_hardening INTERFACE)
if(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    target_compile_options(kasumi_hardening INTERFACE
        /GS
    )
    target_link_options(kasumi_hardening INTERFACE
        /DYNAMICBASE
        /NXCOMPAT
        /HIGHENTROPYVA
    )
else()
    include(CheckCXXCompilerFlag)
    include(CheckLinkerFlag)
    include(CheckCXXSourceCompiles)

    check_cxx_compiler_flag("-fstack-protector-strong" KASUMI_HAS_STACK_PROTECTOR_STRONG)
    if(KASUMI_HAS_STACK_PROTECTOR_STRONG)
        target_compile_options(kasumi_hardening INTERFACE -fstack-protector-strong)
    endif()

    if(WIN32)
        # Windows MinGW PE hardening
        check_linker_flag(CXX "-Wl,--dynamicbase" KASUMI_HAS_DYNAMICBASE)
        if(KASUMI_HAS_DYNAMICBASE)
            target_link_options(kasumi_hardening INTERFACE
                -Wl,--dynamicbase
                -Wl,--nxcompat
                -Wl,--high-entropy-va
            )
        endif()
    else()
        # Linux ELF hardening
        set(CMAKE_REQUIRED_FLAGS_SAVE "${CMAKE_REQUIRED_FLAGS}")
        set(CMAKE_REQUIRED_FLAGS "-O2")
        check_cxx_source_compiles("
            #define _FORTIFY_SOURCE 3
            #include <string.h>
            int main() { return 0; }
        " KASUMI_HAS_FORTIFY_SOURCE_3)
        if(KASUMI_HAS_FORTIFY_SOURCE_3)
            target_compile_definitions(kasumi_hardening INTERFACE
                $<$<OR:$<CONFIG:Release>,$<CONFIG:MinSizeRel>>:_FORTIFY_SOURCE=3>
            )
        else()
            check_cxx_source_compiles("
                #define _FORTIFY_SOURCE 2
                #include <string.h>
                int main() { return 0; }
            " KASUMI_HAS_FORTIFY_SOURCE_2)
            if(KASUMI_HAS_FORTIFY_SOURCE_2)
                target_compile_definitions(kasumi_hardening INTERFACE
                    $<$<OR:$<CONFIG:Release>,$<CONFIG:MinSizeRel>>:_FORTIFY_SOURCE=2>
                )
            endif()
        endif()
        set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS_SAVE}")

        check_linker_flag(CXX "-Wl,-z,relro" KASUMI_HAS_RELRO)
        if(KASUMI_HAS_RELRO)
            target_link_options(kasumi_hardening INTERFACE -Wl,-z,relro)
        endif()

        check_linker_flag(CXX "-Wl,-z,now" KASUMI_HAS_BIND_NOW)
        if(KASUMI_HAS_BIND_NOW)
            target_link_options(kasumi_hardening INTERFACE -Wl,-z,now)
        endif()
    endif()
endif()

add_library(kasumi_core STATIC
    src/core/hasher.cpp
    src/core/node.cpp
    src/core/operation.cpp
    src/core/diff.cpp
    src/core/history.cpp
    src/core/wire.cpp
    src/core/reconciliation/plan.cpp
    src/core/maintenance.cpp
    src/core/transaction/types.cpp
    src/core/transaction/codec.cpp
)

target_include_directories(
    kasumi_core
    PUBLIC
    include
)

target_link_libraries(
    kasumi_core
    PRIVATE
    blake3
    utf8proc
    kasumi_warnings
    kasumi_release_optimizations
    kasumi_hardening
)

add_library(kasumi_transport STATIC
    src/transport/types.cpp
    src/transport/transport.cpp
    src/transport/local.cpp
    src/transport/local/storage.cpp
    src/transport/rclone.cpp
    src/transport/rclone/storage.cpp
    src/transport/rclone/session.cpp
    src/transport/rclone/rc_client.cpp
)

target_include_directories(
    kasumi_transport
    PUBLIC
    include
)

if(WIN32 AND CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    set_source_files_properties(
        src/transport/rclone/rc_client.cpp
        PROPERTIES COMPILE_OPTIONS "-Wa,-mbig-obj"
    )
endif()

set(KASUMI_EXTRA_SOURCES)
if(WIN32)
    set(CMAKE_RC_FLAGS "${CMAKE_RC_FLAGS} -c 65001")
    list(APPEND KASUMI_EXTRA_SOURCES src/platform/windows/kasumi.rc)
endif()

add_executable(kasumi src/main.cpp ${KASUMI_EXTRA_SOURCES})

if(POLICY CMP0218)
    cmake_policy(SET CMP0218 OLD)
endif()
set(CMAKE_WARN_DEPRECATED OFF)

include(FetchContent)

set(REPROC++ ON CACHE BOOL "" FORCE)
set(REPROC_TEST OFF CACHE BOOL "" FORCE)
set(REPROC_EXAMPLES OFF CACHE BOOL "" FORCE)
set(REPROC_INSTALL OFF CACHE BOOL "" FORCE)

set(HTTPLIB_USE_OPENSSL_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
set(HTTPLIB_USE_ZLIB_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
set(HTTPLIB_USE_BROTLI_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
set(HTTPLIB_USE_ZSTD_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
set(HTTPLIB_INSTALL OFF CACHE BOOL "" FORCE)
set(JSON_Install OFF CACHE BOOL "" FORCE)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)

if(WIN32)
    set(HTTPLIB_USE_NON_BLOCKING_GETADDRINFO OFF CACHE BOOL "" FORCE)
endif()

FetchContent_Declare(
    reproc
    GIT_REPOSITORY https://github.com/DaanDeMeyer/reproc.git
    GIT_TAG 3179928ae7b085e41dfb846d987519fa7c12ffb3
    SYSTEM
)

FetchContent_Declare(
    cpp_httplib
    GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
    GIT_TAG d66d9a95997d51a8ba9822a611d1267757741535
    SYSTEM
)

FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG 55f93686c01528224f448c19128836e7df245f72
    SYSTEM
)

FetchContent_MakeAvailable(
    reproc
    cpp_httplib
    nlohmann_json
)

if(BUILD_TESTING)
    fetchcontent_declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG f8d7d77c06936315286eb55f8de22cd23c188571
        SYSTEM
    )
    fetchcontent_makeavailable(googletest)
endif()

set(UTF8PROC_ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(UTF8PROC_INSTALL OFF CACHE BOOL "" FORCE)

FetchContent_Declare(
    utf8proc
    URL https://github.com/JuliaStrings/utf8proc/archive/refs/tags/v2.11.3.tar.gz
    URL_HASH SHA256=abfed50b6d4da51345713661370290f4f4747263ee73dc90356299dfc7990c78
    DOWNLOAD_EXTRACT_TIMESTAMP true
    SYSTEM
)
FetchContent_MakeAvailable(utf8proc)

fetchcontent_declare(
    blake3
    GIT_REPOSITORY https://github.com/BLAKE3-team/BLAKE3.git
    GIT_TAG f3149ec5bb5449af877ba20377a11008ff499fa2
    SOURCE_SUBDIR c
    EXCLUDE_FROM_ALL
    SYSTEM
)
fetchcontent_makeavailable(blake3)

fetchcontent_declare(
    sqlite_amalgamation
    URL https://www.sqlite.org/2026/sqlite-amalgamation-3530400.zip
    URL_HASH SHA256=1e71ddf93849c6a6ecf58b827c0692073d2dd7ee40196158068f7b29f422e87d
    DOWNLOAD_EXTRACT_TIMESTAMP true
)
fetchcontent_makeavailable(sqlite_amalgamation)
add_library(kasumi_sqlite3 STATIC
    ${sqlite_amalgamation_SOURCE_DIR}/sqlite3.c
)
target_include_directories(kasumi_sqlite3 PUBLIC
    ${sqlite_amalgamation_SOURCE_DIR}
)
if(CMAKE_C_COMPILER_ID MATCHES "GNU")
    target_compile_options(kasumi_sqlite3 PRIVATE -Wno-stringop-overread $<$<CONFIG:Release>:-O2>)
endif()

add_library(kasumi_state_storage STATIC
    src/state_storage/database.cpp
)

target_include_directories(
    kasumi_state_storage
    PUBLIC
    include
    PRIVATE
    ${PROJECT_SOURCE_DIR}/src
)

target_link_libraries(
    kasumi_state_storage
    PUBLIC
    kasumi_core
    kasumi_platform
    PRIVATE
    kasumi_sqlite3
    kasumi_warnings
    kasumi_release_optimizations
    kasumi_hardening
)

fetchcontent_declare(
    monocypher
    URL https://github.com/LoupVaillant/Monocypher/archive/ab2b16dd619ad5f6979a4fbe69cfa324a6fcc35f.zip
    URL_HASH SHA256=3f2a78032686ae8f085bd7892a890e932cf4f6ce42328214ce7aaf14d58b6c18
    DOWNLOAD_EXTRACT_TIMESTAMP true
    SYSTEM
)
fetchcontent_makeavailable(monocypher)

add_library(monocypher STATIC ${monocypher_SOURCE_DIR}/src/monocypher.c)
target_include_directories(monocypher PUBLIC ${monocypher_SOURCE_DIR}/src)

add_library(kasumi_platform STATIC
    src/platform/cancellation.cpp
    src/platform/clock.cpp
    src/platform/change_journal.cpp
    src/platform/durability.cpp
    src/platform/file_fingerprint.cpp
    src/platform/identity.cpp
    src/platform/metadata.cpp
    src/platform/perf_trace.cpp
    src/platform/private_storage.cpp
    src/platform/profile_lock.cpp
    src/platform/random.cpp
    src/platform/workspace.cpp
)

target_include_directories(
    kasumi_platform
    PUBLIC
    include
)

target_link_libraries(
    kasumi_platform
    PRIVATE
    monocypher
    kasumi_warnings
    kasumi_release_optimizations
    kasumi_hardening
)

if(WIN32)
    target_link_libraries(
        kasumi_platform
        PRIVATE
        advapi32
        bcrypt
    )
endif()

target_link_libraries(
    kasumi_transport
    PRIVATE
    httplib::httplib
    nlohmann_json::nlohmann_json
    reproc++
    kasumi_platform
    kasumi_warnings
    kasumi_release_optimizations
    kasumi_hardening
)

add_library(kasumi_crypto STATIC
    src/crypto/content.cpp
    src/crypto/file_crypto.cpp
    src/crypto/key_derivation.cpp
    src/crypto/physical_hash.cpp
    src/crypto/secure_memory.cpp
)

target_include_directories(
    kasumi_crypto
    PUBLIC
    include
)

target_link_libraries(
    kasumi_crypto
    PUBLIC
    kasumi_core
    PRIVATE
    kasumi_platform
    blake3
    monocypher
    kasumi_warnings
    kasumi_release_optimizations
    kasumi_hardening
)

fetchcontent_declare(
    tomlplusplus
    GIT_REPOSITORY https://github.com/marzer/tomlplusplus.git
    GIT_TAG 30172438cee64926dc41fdd9c11fb3ba5b2ba9de
    SYSTEM
)
fetchcontent_makeavailable(tomlplusplus)
set(CMAKE_WARN_DEPRECATED ON)

add_library(kasumi_application STATIC
    src/application/history_storage/epoch.cpp
    src/application/history_storage/history_storage.cpp
    src/application/history_storage/inventory.cpp
    src/application/history_storage/loading.cpp
    src/application/history_storage/reachability.cpp
    src/application/history_storage/content_reachability.cpp
    src/application/history_storage/maintenance_protocol.cpp
    src/application/history_storage/publication.cpp
    src/application/history_storage/cleanup.cpp
    src/application/observation/scanner.cpp
    src/application/observation/patch.cpp
    src/application/observation/state.cpp
    src/application/observation/history.cpp
    src/application/sync/journal.cpp
    src/application/sync/mutation.cpp
    src/application/sync/mutation_detail.cpp
    src/application/sync/mutation_batch.cpp
    src/application/sync/mutation_transaction.cpp
    src/application/sync/metadata.cpp
    src/application/sync/publication.cpp
    src/application/sync/reobservation.cpp
    src/application/sync/coordinator.cpp
    src/application/sync/coordinator_recovery.cpp
    src/application/integrity/maintenance.cpp
    src/application/inspection/inspect.cpp
    src/application/credentials.cpp
    src/application/environment.cpp
    src/application/execute.cpp
    src/application/profile.cpp
    src/application/use_cases/error_mapping.cpp
    src/application/use_cases/context.cpp
    src/application/use_cases/maintenance.cpp
    src/application/use_cases/plan.cpp
    src/application/use_cases/sync.cpp
)

target_include_directories(
    kasumi_application
    PUBLIC
    include
    PRIVATE
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>
)

target_link_libraries(kasumi_application
    PRIVATE
    kasumi_runtime
    kasumi_core
    kasumi_transport
    kasumi_platform
    kasumi_crypto
    kasumi_state_storage
    monocypher
    kasumi_warnings
    kasumi_release_optimizations
    kasumi_hardening
)

add_library(kasumi_runtime STATIC
    src/runtime/paths.cpp
    src/runtime/profile.cpp
    src/runtime/resolver.cpp
    src/runtime/vault.cpp
)

target_include_directories(kasumi_runtime PUBLIC include)

target_link_libraries(kasumi_runtime
    PRIVATE
    kasumi_platform
    tomlplusplus::tomlplusplus
    monocypher
    kasumi_warnings
    kasumi_release_optimizations
    kasumi_hardening
)

add_library(kasumi_cli STATIC
    src/cli/app.cpp
    src/cli/credentials.cpp
    src/cli/i18n.cpp
    src/cli/parser.cpp
    src/cli/presenter.cpp
    src/cli/wizard.cpp
)

file(READ "${PROJECT_SOURCE_DIR}/locales/en.json" KASUMI_I18N_EN_JSON)
file(READ "${PROJECT_SOURCE_DIR}/locales/pt-BR.json" KASUMI_I18N_PT_BR_JSON)
configure_file(
    "${PROJECT_SOURCE_DIR}/src/cli/i18n_embedded.hpp.in"
    "${PROJECT_BINARY_DIR}/generated/cli/i18n_embedded.hpp"
    @ONLY
)

target_include_directories(
    kasumi_cli
    PUBLIC
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_BINARY_DIR}/generated
    PRIVATE
    ${PROJECT_SOURCE_DIR}/src
)

target_link_libraries(
    kasumi_cli
    PUBLIC
    kasumi_application
    PRIVATE
    kasumi_warnings
    kasumi_release_optimizations
    kasumi_hardening
    nlohmann_json::nlohmann_json
)
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND WIN32)
    target_link_libraries(kasumi_cli PRIVATE stdc++exp)
endif()

target_compile_definitions(kasumi_cli PRIVATE "KASUMI_VERSION=\"${PROJECT_VERSION}\"")

target_link_libraries(
    kasumi
    PRIVATE
    kasumi_cli
    kasumi_warnings
    kasumi_release_optimizations
    kasumi_hardening
)

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND WIN32)
    target_link_options(kasumi PRIVATE
        $<$<OR:$<CONFIG:Release>,$<CONFIG:MinSizeRel>>:-static>
    )
endif()

set(KASUMI_FIRST_PARTY_TARGETS
    kasumi_core
    kasumi_transport
    kasumi_state_storage
    kasumi_platform
    kasumi_crypto
    kasumi_application
    kasumi_runtime
    kasumi_cli
    kasumi
)

set_target_properties(${KASUMI_FIRST_PARTY_TARGETS} PROPERTIES POSITION_INDEPENDENT_CODE TRUE)

include(CheckIPOSupported)
check_ipo_supported(RESULT ipo_supported)
if(ipo_supported AND NOT (CMAKE_CXX_COMPILER_ID MATCHES "GNU" AND WIN32))
    set_target_properties(${KASUMI_FIRST_PARTY_TARGETS} PROPERTIES INTERPROCEDURAL_OPTIMIZATION TRUE)
endif()

include(GNUInstallDirs)
install(
    TARGETS kasumi
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    COMPONENT kasumi
)

if(BUILD_TESTING)
    if(KASUMI_BUILD_SYSTEM_TESTS)
        find_program(KASUMI_RCLONE_EXECUTABLE NAMES rclone)
        if(NOT KASUMI_RCLONE_EXECUTABLE)
            message(FATAL_ERROR
                "KASUMI_BUILD_SYSTEM_TESTS=ON requires the rclone executable")
        endif()
    endif()
    add_subdirectory(tests)
endif()
