if(NOT EXISTS "${DEST}")
  configure_file("${SOURCE}" "${DEST}" COPYONLY)
endif()
