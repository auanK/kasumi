include(GoogleTest)

function(kasumi_add_test_suite target label)
    cmake_parse_arguments(
        ARG "" "" "SOURCES;LIBRARIES" ${ARGN}
    )

    if(NOT ARG_SOURCES OR NOT ARG_LIBRARIES)
        message(
            FATAL_ERROR
            "${target} requires SOURCES and LIBRARIES"
        )
    endif()

    add_executable(
        ${target}
        ${ARG_SOURCES}
    )

    target_link_libraries(
        ${target}
        PRIVATE
        GTest::gtest_main
        ${ARG_LIBRARIES}
        kasumi_test_support
        kasumi_warnings
    )

    target_include_directories(${target} PRIVATE ${PROJECT_SOURCE_DIR}/src)

    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND WIN32)
        target_link_options(${target} PRIVATE -static-libgcc -static-libstdc++ -Wl,--allow-multiple-definition)
    endif()

    gtest_discover_tests(
        ${target}
        DISCOVERY_MODE PRE_TEST
        DISCOVERY_TIMEOUT 30
        PROPERTIES LABELS "${label}"
    )
endfunction()

add_subdirectory(support)

kasumi_add_test_suite(
    kasumi_test_unit_platform
    "unit.platform"
    SOURCES
        unit/platform/test_path.cpp
        unit/platform/test_metadata.cpp
        unit/platform/test_file_fingerprint.cpp
        unit/platform/test_private_storage.cpp
    LIBRARIES
        kasumi_platform
)

kasumi_add_test_suite(
    kasumi_test_unit_application_observation
    "unit.application.observation"
    SOURCES
        unit/application/observation/test_history.cpp
        unit/application/observation/test_scanner.cpp
    LIBRARIES
        kasumi_application
)

kasumi_add_test_suite(
    kasumi_test_unit_application
    "unit.application"
    SOURCES
        unit/application/test_profile.cpp
        unit/application/test_execute.cpp
        unit/application/test_inspection.cpp
        unit/application/integrity/test_maintenance.cpp
    LIBRARIES
        kasumi_application
)

kasumi_add_test_suite(
    kasumi_test_integration_sync
    "integration.sync"
    SOURCES
        integration/sync/test_coordinator.cpp
        integration/sync/test_content_batch.cpp
        integration/sync/test_publication.cpp
    LIBRARIES
        kasumi_application
        kasumi_sqlite3
)

kasumi_add_test_suite(
    kasumi_test_e2e_local_sync
    "e2e.local_sync"
    SOURCES
        e2e/local_sync/test_sync.cpp
    LIBRARIES
        kasumi_application
)

kasumi_add_test_suite(
    kasumi_test_unit_application_history_storage
    "unit.application.history_storage"
    SOURCES
        unit/application/history_storage/test_epoch.cpp
        unit/application/history_storage/test_epoch_planner.cpp
        unit/application/history_storage/test_history_storage.cpp
        unit/application/history_storage/test_content_reachability.cpp
        unit/application/history_storage/test_codec_fuzz.cpp
        unit/application/history_storage/test_reachability.cpp
    LIBRARIES
        kasumi_application
)

kasumi_add_test_suite(
    kasumi_test_unit_crypto
    "unit.crypto"
    SOURCES
        unit/crypto/test_content.cpp
        unit/crypto/test_secure_memory.cpp
    LIBRARIES
        kasumi_crypto
)

kasumi_add_test_suite(
    kasumi_test_unit_state_storage
    "unit.state_storage"
    SOURCES
        unit/state_storage/test_database.cpp
    LIBRARIES
        kasumi_state_storage
        kasumi_sqlite3
)

kasumi_add_test_suite(
    kasumi_test_unit_cli
    "unit.cli"
    SOURCES
        unit/cli/test_credentials.cpp
        unit/cli/test_i18n.cpp
        unit/cli/test_parser.cpp
        unit/cli/test_presenter.cpp
    LIBRARIES
        kasumi_cli
)

kasumi_add_test_suite(
    kasumi_test_unit_core_diff
    "unit.core.diff"
    SOURCES
        unit/core/diff/test_diff.cpp
    LIBRARIES
        kasumi_core
)

kasumi_add_test_suite(
    kasumi_test_unit_core_persistence
    "unit.core.persistence"
    SOURCES
        unit/core/persistence/test_transaction.cpp
        unit/core/persistence/test_history.cpp
    LIBRARIES
        kasumi_core
)

kasumi_add_test_suite(
    kasumi_test_unit_core_primitives
    "unit.core.primitives"
    SOURCES
        unit/core/primitives/test_hasher.cpp
        unit/core/primitives/test_node.cpp
        unit/core/primitives/test_operation.cpp
        unit/core/primitives/test_wire.cpp
    LIBRARIES
        kasumi_core
)

kasumi_add_test_suite(
    kasumi_test_unit_runtime
    "unit.runtime"
    SOURCES
        unit/runtime/test_paths_profile.cpp
        unit/runtime/test_resolver.cpp
        unit/runtime/test_vault.cpp
    LIBRARIES
        kasumi_runtime
)

kasumi_add_test_suite(
    kasumi_test_unit_transport
    "unit.transport"
    SOURCES
        unit/transport/test_local.cpp
        unit/transport/test_rclone_storage.cpp
    LIBRARIES
        kasumi_transport
        nlohmann_json::nlohmann_json
        httplib::httplib
        reproc++
)

kasumi_add_test_suite(
    kasumi_test_integration_runtime_application
    "integration.runtime_application"
    SOURCES
        integration/runtime_application/test_runtime_application.cpp
    LIBRARIES
        kasumi_application
)

kasumi_add_test_suite(
    kasumi_test_integration_contracts
    "integration.contracts"
    SOURCES
        integration/contracts/test_application_contracts.cpp
        integration/contracts/test_remote_heads.cpp
        integration/contracts/test_sync_maintenance.cpp
    LIBRARIES
        kasumi_application
        kasumi_cli
)

if(KASUMI_BUILD_SYSTEM_TESTS)
    kasumi_add_test_suite(
        kasumi_test_system_rclone
        "system.rclone"
        SOURCES
            system/rclone/test_rclone_system.cpp
        LIBRARIES
            kasumi_application
            nlohmann_json::nlohmann_json
            reproc++
    )

    target_compile_definitions(
        kasumi_test_system_rclone
        PRIVATE
        KASUMI_SYSTEM_RCLONE_EXECUTABLE="${KASUMI_RCLONE_EXECUTABLE}"
        KASUMI_SYSTEM_KASUMI_EXECUTABLE="$<TARGET_FILE:kasumi>"
    )
    add_dependencies(kasumi_test_system_rclone kasumi)
endif()

add_test(
    NAME kasumi_architecture_dag
    COMMAND
        ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${PROJECT_SOURCE_DIR}
        -P ${PROJECT_SOURCE_DIR}/tests/architecture/check_dependency_dag.cmake
)

if(KASUMI_BUILD_BENCHMARKS)
add_executable(
    kasumi_benchmark_local_scan
    operational/benchmark_local_scan.cpp
)

target_link_libraries(
    kasumi_benchmark_local_scan
    PRIVATE
    kasumi_application
    kasumi_warnings
)

target_include_directories(
    kasumi_benchmark_local_scan
    PRIVATE
    ${PROJECT_SOURCE_DIR}/src
)

if(WIN32)
    target_link_libraries(kasumi_benchmark_local_scan PRIVATE psapi)
endif()

add_executable(
    kasumi_benchmark_structural_scale
    operational/benchmark_structural_scale.cpp
)

target_link_libraries(
    kasumi_benchmark_structural_scale
    PRIVATE
    kasumi_core
    kasumi_crypto
    kasumi_platform
    kasumi_state_storage
    kasumi_warnings
)

target_include_directories(
    kasumi_benchmark_structural_scale
    PRIVATE
    ${PROJECT_SOURCE_DIR}/src
)

add_executable(
    kasumi_benchmark_sync_e2e
    operational/benchmark_sync_e2e.cpp
)
target_link_libraries(
    kasumi_benchmark_sync_e2e
    PRIVATE
    kasumi_application
    kasumi_warnings
)
target_include_directories(
    kasumi_benchmark_sync_e2e
    PRIVATE
    ${PROJECT_SOURCE_DIR}/src
    ${PROJECT_SOURCE_DIR}/include
)

endif()

set_property(DIRECTORY APPEND PROPERTY TEST_INCLUDE_FILES "${CMAKE_CURRENT_LIST_DIR}/release_critical_labels.cmake")
