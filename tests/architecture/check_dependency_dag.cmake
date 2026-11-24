cmake_minimum_required(VERSION 3.28)

if(NOT DEFINED PROJECT_SOURCE_DIR)
    message(FATAL_ERROR "PROJECT_SOURCE_DIR is required")
endif()

function(assert_tree_excludes root pattern reason)
    file(GLOB_RECURSE files LIST_DIRECTORIES false
        "${PROJECT_SOURCE_DIR}/${root}/*.c"
        "${PROJECT_SOURCE_DIR}/${root}/*.cpp"
        "${PROJECT_SOURCE_DIR}/${root}/*.h"
        "${PROJECT_SOURCE_DIR}/${root}/*.hpp")
    foreach(path IN LISTS files)
        file(READ "${path}" text)
        if(text MATCHES "${pattern}")
            file(RELATIVE_PATH relative "${PROJECT_SOURCE_DIR}" "${path}")
            message(FATAL_ERROR "${reason}: ${relative}")
        endif()
    endforeach()
endfunction()

function(assert_file_excludes path pattern reason)
    file(READ "${PROJECT_SOURCE_DIR}/${path}" text)
    if(text MATCHES "${pattern}")
        message(FATAL_ERROR "${reason}: ${path}")
    endif()
endfunction()

function(assert_no_includes root forbidden)
    assert_tree_excludes(
        "${root}"
        "#include[ \t]+[\"<](${forbidden})/"
        "forbidden dependency include")
endfunction()

assert_no_includes(include/core "application|cli|runtime|transport")
assert_no_includes(src/core "application|cli|runtime|transport")
assert_no_includes(include/runtime "application|cli|core|transport")
assert_no_includes(src/runtime "application|cli|core|transport")
assert_no_includes(include/transport "application|cli|core|runtime")
assert_no_includes(src/transport "application|cli|core|runtime")
assert_no_includes(src/cli "core|runtime|transport")
assert_no_includes(src/application/history_storage
                   "application/(coordination|observation|sync)")

set(obsolete_observation "ChangeJournal|ObservationCheckpoint|DirectoryLineageView|LocalDeltaDisposition|ChangeEvidence|directory_file_reference|apply_local_delta|FSCTL_[A-Z_]*USN|USN_RECORD")
assert_tree_excludes(src "${obsolete_observation}"
                     "obsolete local observation dependency")
assert_tree_excludes(include "${obsolete_observation}"
                     "obsolete local observation interface")

file(GLOB_RECURSE public_application_headers LIST_DIRECTORIES false
     RELATIVE "${PROJECT_SOURCE_DIR}/include/application"
     "${PROJECT_SOURCE_DIR}/include/application/*.hpp")
list(SORT public_application_headers)
set(expected_public_application_headers
    credentials.hpp
    daemon.hpp
    environment.hpp
    execute.hpp
    inspection/inspect.hpp
    inspection/request.hpp
    inspection/result.hpp
    profile.hpp
    request.hpp
    result.hpp)
if(NOT "${public_application_headers}" STREQUAL
   "${expected_public_application_headers}")
    message(FATAL_ERROR "public Application API surface changed")
endif()

file(GLOB_RECURSE public_cli_headers LIST_DIRECTORIES false
     RELATIVE "${PROJECT_SOURCE_DIR}/include/cli"
     "${PROJECT_SOURCE_DIR}/include/cli/*.hpp")
if(NOT "${public_cli_headers}" STREQUAL "app.hpp")
    message(FATAL_ERROR "public CLI facade surface changed")
endif()
if(EXISTS "${PROJECT_SOURCE_DIR}/include/application/sync" OR
   EXISTS "${PROJECT_SOURCE_DIR}/include/application/history_storage" OR
   EXISTS "${PROJECT_SOURCE_DIR}/include/application/coordination")
    message(FATAL_ERROR "private Application implementation became public")
endif()

assert_tree_excludes(
    tests/system
    "pkill|killall|taskkill[ \t]+/IM|RCLONE_RC_ADDR[^\n]*:[ \t]*[0-9][0-9]+"
    "unsafe external rclone process control")

foreach(path IN ITEMS
        src/application/history_storage/reachability.cpp
        src/application/history_storage/content_reachability.cpp)
    assert_file_excludes(
        "${path}"
        "transport::(put|remove)|state_storage|journal::|coordinator::"
        "read-only reachability crossed a mutation boundary")
endforeach()

assert_tree_excludes(src "manifest\\.kasumi"
                     "mutable manifest returned to production")
assert_tree_excludes(include "manifest\\.kasumi"
                     "mutable manifest returned to production")
assert_tree_excludes(src/core "history/commits/|history/heads/|KHED"
                     "Core knows History Storage layout")
assert_tree_excludes(src/application/sync "history/commits/|history/heads/|KHED"
                     "Sync duplicates History Storage layout")
assert_file_excludes(
    src/state_storage/database.cpp
    "DELETE FROM nodes[ \t\r\n]*(;|\")"
    "authoritative node persistence must remain delta-based")

function(assert_tree_no_oop root)
    file(GLOB_RECURSE files LIST_DIRECTORIES false
        "${PROJECT_SOURCE_DIR}/${root}/*.c"
        "${PROJECT_SOURCE_DIR}/${root}/*.cpp"
        "${PROJECT_SOURCE_DIR}/${root}/*.h"
        "${PROJECT_SOURCE_DIR}/${root}/*.hpp")
    foreach(path IN LISTS files)
        file(READ "${path}" text)
        string(REGEX REPLACE "//[^\n]*" "" cleaned "${text}")
        string(REGEX REPLACE "\"([^\"\\\\]|\\\\.)*\"" "\"\"" cleaned "${cleaned}")
        string(REGEX REPLACE "enum[ \t]+class" "enum__class" cleaned "${cleaned}")
        file(RELATIVE_PATH relative "${PROJECT_SOURCE_DIR}" "${path}")
        if(cleaned MATCHES "(^|[^A-Za-z0-9_])class[ \t]+[A-Za-z_][A-Za-z0-9_]*[ \t\r\n]*[:{;]")
            message(FATAL_ERROR "OOP class declaration forbidden by DoD architecture: ${relative}")
        endif()
        if(cleaned MATCHES "(^|\n)[ \t]*(public|private|protected)[ \t]*:")
            message(FATAL_ERROR "OOP visibility specifier forbidden by DoD architecture: ${relative}")
        endif()
        if(cleaned MATCHES "(^|[^A-Za-z0-9_])(virtual|friend)[ \t]+")
            message(FATAL_ERROR "OOP virtual/friend keyword forbidden by DoD architecture: ${relative}")
        endif()
    endforeach()
endfunction()

assert_tree_no_oop(include)
assert_tree_no_oop(src)
