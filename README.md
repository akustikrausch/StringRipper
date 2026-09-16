# StringRipper

Pulls URLs and regex matches out of a running process or out of files and
folders. Windows only. One portable, unsigned exe, no DLLs, no installer.

Rips through ASCII/ANSI/UTF-8, UTF-16 (LE/BE) and one level of Base64 and Hex,
de-dups, groups (by domain or pattern), sorts Z to A.

- URL mode: `scheme://host` for http, https, ftp(s), ws(s), rtsp, rtmp, mms, udp.
  The host must be real (domain + TLD, dotted IPv4, or localhost), so
  `://`-shaped junk is dropped.
- Regex mode: presets (email, IPv4, IPv6, GUID, API key, file path) plus a custom
  ECMAScript pattern.

Findings are plain text: no click-to-open. Save as TXT and Send to editor write
the file straight to disk, never through the clipboard, so a background download
manager cannot grab the links. Only Copy selected uses the clipboard. It reads
readable memory of processes the current user may open; it never writes to
another process, injects, or touches the OS security core.

Export is the window's grouped view minus the encoding/source columns: a
`domain (count)` line, its URLs flush-left beneath, one per line.

## Reader from FXChainPlayer

Process reading is FXChainPlayer's ripper backend
(`src/audio/rip_backend_win32.cpp` via the `IMemoryReader` seam): region walk,
integrity, image classification, UAC relaunch. It is compiled from a
FXChainPlayer checkout, not vendored. StringRipper's own code is the scan (a
worker pool of `cores - 2`, `scan_driver.hpp`) and the detector (`scan_core.hpp`,
hand-rolled URL scan, `std::regex` only for patterns). ~277 MB/s URL, ~37 MB/s
regex on 32 cores.

## Build

MSVC C++ build tools and a FXChainPlayer checkout. `FXCHAINPLAYER_DIR` points at
it, default `..\VST-Player`.

```
pwsh -File build.ps1
```

`bin\StringRipper.exe`, static CRT, LTO. A prebuilt copy is in `bin\`. CMake
also works: `cmake -DFXCHAINPLAYER_DIR=<checkout>`.

## Usage

Run with no arguments for the window: filter/pick a process (or a file), URL or
Regex, tick encodings, Scan. Command line:

```
StringRipper.exe --pid 4821
StringRipper.exe --file game.exe --preset email,apikey
StringRipper.exe --folder .\dump --regex "\bAKIA[0-9A-Z]{16}\b" --out keys.txt
StringRipper.exe --help
```

Higher-integrity processes need an elevated instance.

## Layout

- `src/scan_core.hpp` - detector, platform-free, self-tested.
- `src/scan_driver.hpp` - the worker pool over `IMemoryReader` and files.
- `src/file_read.hpp` - folder expansion.
- `src/main.cpp` - Win32 GUI and CLI.
- `tests/` - core and driver self-tests.
- `CODE_STYLE.md` - how the native code is written.

Akustikrausch.
