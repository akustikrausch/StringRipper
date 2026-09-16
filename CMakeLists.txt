cmake_minimum_required(VERSION 3.20)
project(URLRipper LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT WIN32)
  message(FATAL_ERROR "URLRipper is Windows-only. The portable core (src/scan_core.hpp) can still be unit-tested elsewhere via tests/test_scan.cpp.")
endif()

# Static CRT so the result is a single portable exe with no runtime DLLs.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")

add_executable(URLRipper WIN32
  src/main.cpp
  src/scan_core.hpp
  src/file_read.hpp
  src/win_process.hpp)

target_compile_definitions(URLRipper PRIVATE UNICODE _UNICODE)
if(MSVC)
  target_compile_options(URLRipper PRIVATE /W3 /permissive- /EHsc)
endif()

# Portable core self-test (no Windows APIs).
enable_testing()
add_executable(test_scan tests/test_scan.cpp)
add_test(NAME scan_core COMMAND test_scan)
