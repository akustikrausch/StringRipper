cmake_minimum_required(VERSION 3.20)
project(StringRipper LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# StringRipper reuses FXChainPlayer's ripper reader (the optimized, hardened Win32
# process/memory backend). Point this at your FXChainPlayer checkout; defaults to
# the sibling folder ../VST-Player.
set(FXCHAINPLAYER_DIR "${CMAKE_SOURCE_DIR}/../VST-Player" CACHE PATH "FXChainPlayer source checkout")
set(FX_SRC "${FXCHAINPLAYER_DIR}/src")

if(NOT WIN32)
  message(FATAL_ERROR "StringRipper is Windows-only. The portable core (src/scan_core.hpp) can still be unit-tested elsewhere via tests/test_scan.cpp.")
endif()
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
  src/scan_driver.hpp
  src/file_read.hpp
  src/version.h)

target_include_directories(StringRipper PRIVATE "${FX_SRC}")
target_compile_definitions(StringRipper PRIVATE UNICODE _UNICODE)
if(MSVC)
  target_compile_options(StringRipper PRIVATE /W3 /permissive- /EHsc)
endif()

# Portable core self-test (no Windows APIs, no FXChainPlayer).
enable_testing()
add_executable(test_scan tests/test_scan.cpp)
add_test(NAME scan_core COMMAND test_scan)

# Driver test: runs the multi-threaded scan over a mock IMemoryReader (needs the
# FXChainPlayer headers for the interface, but opens no real process).
add_executable(test_driver tests/test_driver.cpp)
target_include_directories(test_driver PRIVATE "${FX_SRC}" src)
add_test(NAME scan_driver COMMAND test_driver)
