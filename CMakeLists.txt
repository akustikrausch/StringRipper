cmake_minimum_required(VERSION 3.20)
project(StringRipper LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# StringRipper reuses FXChainPlayer's ripper reader (the optimized, hardened Win32
# process/memory backend). Point this at your FXChainPlayer checkout; defaults to
# the sibling folder ../VST-Player.
set(FXCHAINPLAYER_DIR "${CMAKE_SOURCE_DIR}/../VST-Player" CACHE PATH "FXChainPlayer source checkout")
set(FX_SRC "${FXCHAINPLAYER_DIR}/src")
set(SQLITE_DIR "${FXCHAINPLAYER_DIR}/third_party/sqlite")
if(NOT WIN32)
  find_package(SQLite3 QUIET)
endif()
if(NOT WIN32 AND SQLite3_FOUND)
  add_library(sr_sqlite INTERFACE)
  target_link_libraries(sr_sqlite INTERFACE SQLite::SQLite3)
elseif(EXISTS "${SQLITE_DIR}/sqlite3.c")
  add_library(sr_sqlite STATIC "${SQLITE_DIR}/sqlite3.c")
  target_include_directories(sr_sqlite PUBLIC "${SQLITE_DIR}")
  target_compile_definitions(sr_sqlite PRIVATE SQLITE_THREADSAFE=1 SQLITE_OMIT_LOAD_EXTENSION)
else()
  message(FATAL_ERROR "SQLite not found: install SQLite3 development files or set -DFXCHAINPLAYER_DIR=<checkout>.")
endif()
add_library(sr_store STATIC src/session_store.cpp)
target_include_directories(sr_store PUBLIC src)
target_link_libraries(sr_store PUBLIC sr_sqlite)

if(WIN32)
  if(NOT EXISTS "${FX_SRC}/audio/rip_backend_win32.cpp")
    message(FATAL_ERROR "FXChainPlayer source not found at ${FX_SRC}. Set -DFXCHAINPLAYER_DIR=<checkout>.")
  endif()

  # Static CRT so the result is a single portable exe with no runtime DLLs.
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")

  add_executable(StringRipper WIN32
    src/main.cpp
    "${FX_SRC}/audio/rip_backend_win32.cpp"    # reused FXChainPlayer ripper backend
    src/StringRipper.rc
    src/scan_core.hpp
    src/regex_presets.hpp
    src/scan_driver.hpp
    src/scan_service.hpp
    src/process_scan_win32.hpp
    src/file_read.hpp
    src/workspace.hpp
    src/session_store.hpp
    src/version.h)

  target_include_directories(StringRipper PRIVATE "${FX_SRC}")
  target_link_libraries(StringRipper PRIVATE sr_store)
  target_compile_definitions(StringRipper PRIVATE UNICODE _UNICODE)
  add_custom_command(TARGET StringRipper POST_BUILD
    COMMAND ${CMAKE_COMMAND}
      "-DSOURCE=${CMAKE_SOURCE_DIR}/regex-user-presets.ini"
      "-DDEST=$<TARGET_FILE_DIR:StringRipper>/regex-user-presets.ini"
      -P "${CMAKE_SOURCE_DIR}/cmake/seed-presets.cmake")
  if(MSVC)
    target_compile_options(StringRipper PRIVATE /W3 /permissive- /EHsc)
  elseif(MINGW)
    set_source_files_properties("${FX_SRC}/audio/rip_backend_win32.cpp"
      PROPERTIES COMPILE_OPTIONS "-include;${CMAKE_SOURCE_DIR}/src/mingw_audio_meter_compat.hpp")
  endif()
else()
  # macOS / Linux: the portable CLI (files and folders; process memory is
  # Windows-only). See docs/MACOS.md and build-macos.sh.
  find_package(Threads REQUIRED)
  add_executable(stringripper src/cli_main.cpp)
  target_include_directories(stringripper PRIVATE src)
  target_link_libraries(stringripper PRIVATE Threads::Threads)
  target_link_libraries(stringripper PRIVATE sr_store)
endif()

# Portable core self-test (no Windows APIs, no FXChainPlayer).
enable_testing()
add_executable(benchmark_scan EXCLUDE_FROM_ALL tests/benchmark_scan.cpp)
target_include_directories(benchmark_scan PRIVATE src)
if(NOT WIN32)
  target_link_libraries(benchmark_scan PRIVATE Threads::Threads)
endif()
add_executable(test_scan tests/test_scan.cpp)
add_test(NAME scan_core COMMAND test_scan)
add_executable(test_presets tests/test_presets.cpp)
target_compile_definitions(test_presets PRIVATE SR_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
add_test(NAME regex_presets COMMAND test_presets)
add_executable(test_features tests/test_features.cpp)
add_test(NAME result_features COMMAND test_features)
add_executable(test_workspace tests/test_workspace.cpp)
target_link_libraries(test_workspace PRIVATE sr_store)
add_test(NAME workspace COMMAND test_workspace)
if(NOT WIN32)
  add_test(NAME cli_features COMMAND ${CMAKE_COMMAND}
    "-DCLI=$<TARGET_FILE:stringripper>" "-DSOURCE=${CMAKE_SOURCE_DIR}" "-DWORK=${CMAKE_BINARY_DIR}"
    -P "${CMAKE_SOURCE_DIR}/tests/cli_features.cmake")
endif()

# Driver test: runs the multi-threaded scan over a mock IMemoryReader (needs the
# FXChainPlayer headers for the interface, but opens no real process). Skipped
# where that checkout is absent (e.g. a bare macOS build box).
if(EXISTS "${FX_SRC}/audio/memory_ripper.h")
  add_executable(test_driver tests/test_driver.cpp)
  target_include_directories(test_driver PRIVATE "${FX_SRC}" src)
  add_test(NAME scan_driver COMMAND test_driver)
endif()
