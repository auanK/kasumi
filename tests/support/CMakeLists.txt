file(
    GLOB_RECURSE kasumi_public_headers
    CONFIGURE_DEPENDS
    RELATIVE "${PROJECT_SOURCE_DIR}/include"
    "${PROJECT_SOURCE_DIR}/include/*.hpp"
)

list(SORT kasumi_public_headers)

file(
    GLOB_RECURSE kasumi_private_headers
    CONFIGURE_DEPENDS
    RELATIVE "${PROJECT_SOURCE_DIR}"
    "${PROJECT_SOURCE_DIR}/src/*.hpp"
)

list(SORT kasumi_private_headers)

set(
    kasumi_header_self_containment_directory
    "${CMAKE_CURRENT_BINARY_DIR}/header_self_containment"
)

file(MAKE_DIRECTORY "${kasumi_header_self_containment_directory}")

set(kasumi_header_self_containment_sources)

foreach(header IN LISTS kasumi_public_headers)
    string(MAKE_C_IDENTIFIER "public_${header}" source_name)

    set(
        source
        "${kasumi_header_self_containment_directory}/${source_name}.cpp"
    )

    file(WRITE "${source}" "#include \"${header}\"\n")

    list(APPEND kasumi_header_self_containment_sources "${source}")
endforeach()

foreach(header IN LISTS kasumi_private_headers)
    string(MAKE_C_IDENTIFIER "private_${header}" source_name)

    set(
        source
        "${kasumi_header_self_containment_directory}/${source_name}.cpp"
    )

    file(WRITE "${source}" "#include \"${header}\"\n")

    list(APPEND kasumi_header_self_containment_sources "${source}")
endforeach()

set_source_files_properties(
    ${kasumi_header_self_containment_sources}
    PROPERTIES GENERATED TRUE
)

add_library(kasumi_test_support STATIC
    src/filesystem.cpp
    src/scoped_environment.cpp
    src/temp_workspace.cpp
    ${kasumi_header_self_containment_sources}
)

target_include_directories(
    kasumi_test_support
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
    ${PROJECT_SOURCE_DIR}
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/src
)

target_link_libraries(kasumi_test_support
    PRIVATE
    httplib::httplib
    reproc++
    kasumi_sqlite3
    kasumi_warnings
)
