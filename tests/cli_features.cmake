file(WRITE "${WORK}/feature-input.txt" "TKT-123456\nTKT-654321\nnot a ticket\n")
set(presets "${SOURCE}/regex-user-presets.ini")
execute_process(COMMAND "${CLI}" --list-user-presets --presets-file "${presets}"
  RESULT_VARIABLE rc OUTPUT_VARIABLE names ERROR_VARIABLE err)
if(NOT rc EQUAL 0 OR NOT names MATCHES "Support ticket IDs" OR NOT names MATCHES "Semantic versions")
  message(FATAL_ERROR "Preset listing failed: ${rc} ${err} ${names}")
endif()
execute_process(COMMAND "${CLI}" --file "${WORK}/feature-input.txt"
  --user-preset "Support ticket IDs" --presets-file "${presets}" --format json
  RESULT_VARIABLE rc OUTPUT_VARIABLE output ERROR_VARIABLE err)
if(NOT rc EQUAL 0)
  message(FATAL_ERROR "Preset scan failed: ${rc} ${err}")
endif()
string(JSON count LENGTH "${output}")
string(JSON group GET "${output}" 0 group)
if(NOT count EQUAL 2 OR NOT group STREQUAL "Support ticket IDs")
  message(FATAL_ERROR "Bad JSON result: ${output}")
endif()
execute_process(COMMAND "${CLI}" --regex "no-match"
  --user-preset "Support ticket IDs" --presets-file "${presets}"
  --file "${WORK}/feature-input.txt" --format json
  RESULT_VARIABLE rc OUTPUT_VARIABLE output)
string(JSON count LENGTH "${output}")
if(NOT rc EQUAL 1 OR NOT count EQUAL 0)
  message(FATAL_ERROR "Explicit options must override the user preset regardless of argument order")
endif()
execute_process(COMMAND "${CLI}" --presets-file "${presets}" --user-preset "missing"
  --file "${WORK}/feature-input.txt" RESULT_VARIABLE rc ERROR_VARIABLE err)
if(NOT rc EQUAL 2)
  message(FATAL_ERROR "Unknown preset must fail")
endif()
execute_process(COMMAND "${CLI}" --format yaml --file "${WORK}/feature-input.txt"
  RESULT_VARIABLE rc ERROR_VARIABLE err)
if(NOT rc EQUAL 2)
  message(FATAL_ERROR "Unknown export format must fail")
endif()
execute_process(COMMAND "${CLI}" --file "${WORK}/feature-input.txt"
  --user-preset "Support ticket IDs" --presets-file "${presets}"
  --format csv --out "${WORK}/feature-output.csv"
  RESULT_VARIABLE rc OUTPUT_VARIABLE output ERROR_VARIABLE err)
file(READ "${WORK}/feature-output.csv" csv)
if(NOT rc EQUAL 0 OR NOT csv MATCHES "group,value,encoding,source" OR NOT csv MATCHES "TKT-123456")
  message(FATAL_ERROR "CSV export failed: ${err}")
endif()
file(REMOVE "${WORK}/feature-sessions.sqlite")
execute_process(COMMAND "${CLI}" --file "${WORK}/feature-input.txt"
  --user-preset "Support ticket IDs" --presets-file "${presets}"
  --save-job "Tickets" --save-session "First" --db "${WORK}/feature-sessions.sqlite"
  RESULT_VARIABLE rc OUTPUT_VARIABLE saved ERROR_VARIABLE err)
if(NOT rc EQUAL 0 OR NOT saved MATCHES "session 1")
  message(FATAL_ERROR "Session/job save failed: ${rc} ${err} ${saved}")
endif()
execute_process(COMMAND "${CLI}" --list-jobs --db "${WORK}/feature-sessions.sqlite"
  RESULT_VARIABLE rc OUTPUT_VARIABLE jobs)
if(NOT rc EQUAL 0 OR NOT jobs MATCHES "Tickets")
  message(FATAL_ERROR "Job listing failed: ${jobs}")
endif()
execute_process(COMMAND "${CLI}" --run-job "Tickets" --db "${WORK}/feature-sessions.sqlite"
  --save-session "Second" RESULT_VARIABLE rc OUTPUT_VARIABLE rerun ERROR_VARIABLE err)
if(NOT rc EQUAL 0 OR NOT rerun MATCHES "session 2")
  message(FATAL_ERROR "Job run failed: ${rc} ${err} ${rerun}")
endif()
execute_process(COMMAND "${CLI}" --open-session 1 --db "${WORK}/feature-sessions.sqlite"
  RESULT_VARIABLE rc OUTPUT_VARIABLE opened)
if(NOT rc EQUAL 0 OR NOT opened MATCHES "TKT-123456")
  message(FATAL_ERROR "Session reopen failed: ${opened}")
endif()
execute_process(COMMAND "${CLI}" --compare-sessions 1 2 --db "${WORK}/feature-sessions.sqlite"
  RESULT_VARIABLE rc OUTPUT_VARIABLE compared)
if(NOT rc EQUAL 0 OR NOT compared MATCHES "Added:" OR NOT compared MATCHES "Removed:")
  message(FATAL_ERROR "Session compare failed: ${compared}")
endif()
execute_process(COMMAND "${CLI}" --file "${WORK}/feature-input.txt"
  --user-preset "Support ticket IDs" --user-preset "Semantic versions"
  --presets-file "${presets}" --format json
  RESULT_VARIABLE rc OUTPUT_VARIABLE combined ERROR_VARIABLE err)
if(NOT rc EQUAL 0 OR NOT combined MATCHES "Support ticket IDs")
  message(FATAL_ERROR "Combined profile failed: ${rc} ${err}")
endif()
