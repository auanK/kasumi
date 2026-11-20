include(GoogleTest)

add_test(NAME kasumi_documentation_hygiene
    COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tests/architecture/test_documentation.py)
set_tests_properties(kasumi_documentation_hygiene PROPERTIES LABELS "architecture")

if(CMAKE_NM AND NOT MSVC)
    add_test(NAME kasumi_fault_hook_isolation
        COMMAND ${CMAKE_COMMAND}
            "-DNM=${CMAKE_NM}"
            "-DAPPLICATION_ARCHIVE=$<TARGET_FILE:kasumi_application>"
            "-DKASUMI_EXECUTABLE=$<TARGET_FILE:kasumi>"
            -P ${PROJECT_SOURCE_DIR}/tests/architecture/check_fault_hook_isolation.cmake
    )
    set_tests_properties(kasumi_fault_hook_isolation PROPERTIES LABELS "architecture")
endif()

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

    if(WIN32)
        target_sources(${target} PRIVATE
            "${PROJECT_BINARY_DIR}/long_path_aware.rc")
        if(MSVC)
            target_link_options(${target} PRIVATE /MANIFEST:NO)
        endif()
    endif()

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

add_library(kasumi_application_fault_test_objects OBJECT
    ${PROJECT_SOURCE_DIR}/src/application/profile_fault_test.cpp
    ${PROJECT_SOURCE_DIR}/src/application/profile.cpp
    ${PROJECT_SOURCE_DIR}/src/application/sync/mutation_detail.cpp
    ${PROJECT_SOURCE_DIR}/src/application/sync/mutation.cpp
    ${PROJECT_SOURCE_DIR}/src/application/sync/mutation_transaction.cpp
    ${PROJECT_SOURCE_DIR}/src/application/sync/coordinator.cpp
    ${PROJECT_SOURCE_DIR}/src/application/sync/reobservation.cpp
    ${PROJECT_SOURCE_DIR}/src/platform/workspace.cpp
)
target_include_directories(kasumi_application_fault_test_objects PRIVATE
    ${PROJECT_SOURCE_DIR}/src
)
target_compile_definitions(kasumi_application_fault_test_objects PRIVATE
    KASUMI_MUTATION_FAULT_TESTS
    KASUMI_WORKSPACE_FAULT_TESTS
)
target_link_libraries(kasumi_application_fault_test_objects PRIVATE
    kasumi_application
    blake3
    monocypher
    kasumi_warnings
    kasumi_release_optimizations
    kasumi_hardening
)

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
        unit/application/observation/test_cache_contract.cpp
        unit/application/observation/test_file_metadata.cpp
        support/src/hash_mutation.cpp
    LIBRARIES
        kasumi_application
        blake3
)

kasumi_add_test_suite(
    kasumi_test_unit_application
    "unit.application"
    SOURCES
        unit/application/test_profile.cpp
        unit/application/test_execute.cpp
        unit/application/test_plan_cache.cpp
        unit/application/test_concurrency.cpp
        unit/application/test_inspection.cpp
        unit/application/integrity/test_maintenance.cpp
        unit/application/integrity/test_garbage_collection.cpp
        unit/application/integrity/test_repack_planner.cpp
        unit/application/integrity/test_repack.cpp
    LIBRARIES
        kasumi_application
        kasumi_sqlite3
)
target_sources(kasumi_test_unit_application PRIVATE
    $<TARGET_OBJECTS:kasumi_application_fault_test_objects>
)
target_compile_definitions(kasumi_test_unit_application PRIVATE
    KASUMI_MUTATION_FAULT_TESTS
)

add_executable(
    kasumi_inspect_snapshot_child
    unit/application/inspect_snapshot_child.cpp
)
target_link_libraries(
    kasumi_inspect_snapshot_child
    PRIVATE kasumi_application kasumi_sqlite3 kasumi_warnings
)
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND WIN32)
    target_link_options(kasumi_inspect_snapshot_child PRIVATE
        -static-libgcc -static-libstdc++ -Wl,--allow-multiple-definition)
endif()
target_compile_definitions(
    kasumi_test_unit_application PRIVATE
    "KASUMI_INSPECT_SNAPSHOT_CHILD_PATH=\"$<TARGET_FILE:kasumi_inspect_snapshot_child>\""
)
add_dependencies(kasumi_test_unit_application kasumi_inspect_snapshot_child)

kasumi_add_test_suite(
    kasumi_test_integration_sync
    "integration.sync"
    SOURCES
        integration/sync/test_coordinator.cpp
        integration/sync/test_crash_recovery.cpp
        integration/sync/test_content_batch.cpp
        integration/sync/test_directory_local_move.cpp
        integration/sync/test_journal_preparation.cpp
        integration/sync/test_journal_incremental.cpp
        integration/sync/test_publication.cpp
        integration/sync/test_remote_availability.cpp
        integration/sync/test_reobservation_safeguards.cpp
        integration/sync/test_mutation_contracts.cpp
        integration/sync/test_local_copy.cpp
    LIBRARIES
        kasumi_application
        kasumi_sqlite3
        monocypher
)
target_sources(kasumi_test_integration_sync PRIVATE
    $<TARGET_OBJECTS:kasumi_application_fault_test_objects>
)
target_compile_definitions(kasumi_test_integration_sync PRIVATE
    KASUMI_MUTATION_FAULT_TESTS
)
if(KASUMI_BUILD_JOURNAL_FAULT_TESTS)
    target_compile_definitions(
        kasumi_test_integration_sync PRIVATE KASUMI_JOURNAL_FAULT_TESTS)
    target_compile_definitions(
        kasumi_application_fault_test_objects PRIVATE KASUMI_JOURNAL_FAULT_TESTS)
endif()
target_compile_definitions(kasumi_test_integration_sync PRIVATE KASUMI_WORKSPACE_FAULT_TESTS)

kasumi_add_test_suite(
    kasumi_test_integration_local_copy
    "integration.local_copy"
    SOURCES
        integration/sync/test_local_copy.cpp
    LIBRARIES
        kasumi_application
        kasumi_sqlite3
        monocypher
)
target_sources(kasumi_test_integration_local_copy PRIVATE
    $<TARGET_OBJECTS:kasumi_application_fault_test_objects>
)
target_compile_definitions(kasumi_test_integration_local_copy PRIVATE
    KASUMI_MUTATION_FAULT_TESTS
    "KASUMI_SYNC_CRASH_HELPER_PATH=\"$<TARGET_FILE:kasumi_sync_gc_crash_child>\""
)
add_dependencies(kasumi_test_integration_local_copy kasumi_sync_gc_crash_child)


add_executable(
    kasumi_sync_gc_crash_child
    operational/sync_gc_crash_child.cpp
)
target_sources(kasumi_sync_gc_crash_child PRIVATE
    $<TARGET_OBJECTS:kasumi_application_fault_test_objects>
)
target_link_libraries(
    kasumi_sync_gc_crash_child
    PRIVATE kasumi_application kasumi_sqlite3 monocypher kasumi_warnings
)
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND WIN32)
    target_link_options(kasumi_sync_gc_crash_child PRIVATE
        -static-libgcc -static-libstdc++ -Wl,--allow-multiple-definition)
endif()
target_include_directories(kasumi_sync_gc_crash_child PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_compile_definitions(kasumi_sync_gc_crash_child PRIVATE
    KASUMI_PROCESS_CRASH_TESTS
    KASUMI_MUTATION_FAULT_TESTS
)
if(WIN32)
    target_sources(kasumi_sync_gc_crash_child PRIVATE
        "${PROJECT_BINARY_DIR}/long_path_aware.rc")
    if(MSVC)
        target_link_options(kasumi_sync_gc_crash_child PRIVATE /MANIFEST:NO)
    endif()
endif()
target_compile_definitions(
    kasumi_test_integration_sync
    PRIVATE "KASUMI_SYNC_CRASH_HELPER_PATH=\"$<TARGET_FILE:kasumi_sync_gc_crash_child>\"")
add_dependencies(kasumi_test_integration_sync kasumi_sync_gc_crash_child)
add_test(
    NAME kasumi_crash_hook_isolation
    COMMAND ${CMAKE_COMMAND}
        "-DKASUMI_EXECUTABLE=$<TARGET_FILE:kasumi>"
        "-DCRASH_HELPER=$<TARGET_FILE:kasumi_sync_gc_crash_child>"
        -P ${PROJECT_SOURCE_DIR}/tests/architecture/check_crash_hook_isolation.cmake
)

kasumi_add_test_suite(
    kasumi_test_e2e_local_sync
    "e2e.local_sync"
    SOURCES
        e2e/local_sync/test_sync.cpp
        support/src/provider_scenarios.cpp
        support/src/hash_mutation.cpp
    LIBRARIES
        kasumi_application
        blake3
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
        unit/application/history_storage/test_remote_layout.cpp
        unit/application/history_storage/test_maintenance_protocol.cpp
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
        unit/cli/test_interface.cpp
        unit/cli/test_parser.cpp
        unit/cli/test_presenter.cpp
    LIBRARIES
        kasumi_cli
)

# Substitute Application entry points to exercise CLI outcomes without I/O.
kasumi_add_test_suite(
    kasumi_test_cli_boundary
    "unit.cli"
    SOURCES unit/cli/test_boundary.cpp
    LIBRARIES kasumi_cli
)

add_test(NAME kasumi_cli_process_contract
    COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tests/integration/cli/test_process.py
        --binary $<TARGET_FILE:kasumi>)
set_tests_properties(kasumi_cli_process_contract PROPERTIES LABELS "integration.cli")

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
    kasumi_test_unit_core_ignore
    "unit.core.ignore"
    SOURCES
        unit/core/ignore/test_ignore.cpp
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
        support/src/transport_scenarios.cpp
        unit/transport/test_rclone_storage.cpp
    LIBRARIES
        kasumi_transport
        kasumi_platform
        nlohmann_json::nlohmann_json
        httplib::httplib
        reproc++
)

if(MINGW AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(kasumi_test_unit_transport PRIVATE -Wa,-mbig-obj)
endif()

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
        integration/contracts/test_cli.cpp
        integration/contracts/test_remote_heads.cpp
        integration/contracts/test_sync_maintenance.cpp
        support/src/provider_scenarios.cpp
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

set_property(DIRECTORY APPEND PROPERTY TEST_INCLUDE_FILES "${CMAKE_CURRENT_LIST_DIR}/release_critical_labels.cmake")
