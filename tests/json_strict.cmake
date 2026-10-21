execute_process(COMMAND "${FEATURES}" --invalid-json
  RESULT_VARIABLE rc OUTPUT_VARIABLE json ERROR_VARIABLE err)
if(NOT rc EQUAL 0)
  message(FATAL_ERROR "JSON fixture failed: ${err}")
endif()
string(JSON context ERROR_VARIABLE parseError GET "${json}" 0 contextBefore)
if(parseError OR NOT context STREQUAL "ü")
  message(FATAL_ERROR "Invalid UTF-8 was not escaped into strict JSON: ${parseError}")
endif()
