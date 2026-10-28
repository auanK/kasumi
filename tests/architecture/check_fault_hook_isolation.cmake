foreach(required NM APPLICATION_ARCHIVE KASUMI_EXECUTABLE)
    if(NOT DEFINED ${required} OR "${${required}}" STREQUAL "")
        message(FATAL_ERROR "${required} is required")
    endif()
endforeach()

foreach(artifact IN ITEMS "${APPLICATION_ARCHIVE}" "${KASUMI_EXECUTABLE}")
    if(NOT EXISTS "${artifact}")
        message(FATAL_ERROR "production artifact is missing: ${artifact}")
    endif()
    foreach(kind IN ITEMS --defined-only --undefined-only)
        execute_process(
            COMMAND "${NM}" --demangle ${kind} "${artifact}"
            RESULT_VARIABLE result
            OUTPUT_VARIABLE symbols
            ERROR_VARIABLE error
        )
        if(NOT result EQUAL 0)
            message(FATAL_ERROR "nm failed for ${artifact}: ${error}")
        endif()
        if(symbols MATCHES "kasumi::application::fault_test::")
            message(FATAL_ERROR
                "production artifact depends on profile fault injection: ${artifact}")
        endif()
    endforeach()
endforeach()
