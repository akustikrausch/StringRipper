#!/usr/bin/env bash
# Cross-build a portable Windows x64 GUI release when MSVC is unavailable.
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
fx=${FXCHAINPLAYER_DIR:-"$root/../VST-Player"}
out_dir=${1:-"$root/bin"}
tmp_dir=$(mktemp -d)
trap 'rm -r -- "$tmp_dir"' EXIT

mkdir -p -- "$out_dir"
common=(-O2 -DUNICODE -D_UNICODE -D_WIN32_WINNT=0x0A00 -DWINVER=0x0A00)
cxx=x86_64-w64-mingw32-g++
cc=x86_64-w64-mingw32-gcc

"$cxx" -std=c++20 "${common[@]}" -I"$fx/src" -I"$fx/third_party/sqlite" \
  -c "$root/src/main.cpp" -o "$tmp_dir/main.o"
"$cxx" -std=c++20 "${common[@]}" -I"$fx/third_party/sqlite" \
  -c "$root/src/session_store.cpp" -o "$tmp_dir/session_store.o"
"$cxx" -std=c++20 "${common[@]}" -I"$fx/src" \
  -include "$root/src/mingw_audio_meter_compat.hpp" \
  -c "$fx/src/audio/rip_backend_win32.cpp" -o "$tmp_dir/rip_backend.o"
"$cc" -O2 -DSQLITE_THREADSAFE=1 -DSQLITE_OMIT_LOAD_EXTENSION \
  -c "$fx/third_party/sqlite/sqlite3.c" -o "$tmp_dir/sqlite3.o"
x86_64-w64-mingw32-windres -I "$root/src" -i "$root/src/StringRipper.rc" \
  -o "$tmp_dir/StringRipper.res" -O coff
"$cxx" -O2 -static -static-libgcc -static-libstdc++ -mwindows -municode \
  "$tmp_dir/main.o" "$tmp_dir/session_store.o" "$tmp_dir/rip_backend.o" \
  "$tmp_dir/sqlite3.o" "$tmp_dir/StringRipper.res" \
  -o "$out_dir/StringRipper.exe" \
  -lcomctl32 -lcomdlg32 -lgdi32 -lole32 -loleaut32 -lshell32 -lshlwapi \
  -lpsapi -ladvapi32 -luuid -lws2_32 -lwinmm -luxtheme -ldwmapi

if [[ ! -e "$out_dir/regex-user-presets.ini" ]]; then
  cp -- "$root/regex-user-presets.ini" "$out_dir/regex-user-presets.ini"
fi
printf 'Built %s\n' "$out_dir/StringRipper.exe"
