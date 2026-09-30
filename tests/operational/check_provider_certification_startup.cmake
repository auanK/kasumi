execute_process(
    COMMAND "${KASUMI_PROVIDER_CERTIFICATION_EXECUTABLE}" --target unsupported
    RESULT_VARIABLE result
    OUTPUT_VARIABLE output
    ERROR_VARIABLE error
)

if(NOT "${result}" STREQUAL "2" OR
   NOT "${error}" MATCHES "unsupported target: unsupported")
    message(FATAL_ERROR
        "provider certification runner did not reach its CLI error path "
        "(result='${result}', stdout='${output}', stderr='${error}')")
endif()
