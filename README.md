# URLRipper

Portable Windows tool that pulls **URLs** (and, in regex mode, arbitrary
patterns) out of a **running process** or out of **files and folders**. It
decodes several encodings on the way, de-duplicates the hits, groups them and
sorts them Z to A.

Useful for:

- checking which servers an app talks to (spotting software that phones home),
- finding extra in-app download links or stream URLs,
- a general pattern sweep (emails, IPs, GUIDs, API-key shapes, file paths, or
  your own regex).

It is a **single portable .exe**. No installer, no dependencies, no DLLs to ship
next to it (the C runtime is linked statically). Windows only.

## Why it is its own tool

This started as a feature idea for [FXChainPlayer](https://akustikrausch.itch.io/fxchainplayer)
and was deliberately kept **out** of it. A music player that reads other
processes' memory looking for URLs and key-shaped strings is exactly the kind of
behaviour endpoint security flags, and FXChainPlayer's signing reputation should
not carry that weight. URLRipper is therefore a separate, standalone, **unsigned**
program. Expect SmartScreen or an antivirus to warn about an unsigned tool that
reads process memory; that is the nature of this class of tool.

## What it detects

- **Encodings:** printable ASCII / ANSI / UTF-8, UTF-16 (LE and BE), plus one
  level of **Base64** and **Hex** decoding (an embedded run is decoded and
  re-scanned, and the finding is labelled with the encoding it was hidden
  behind).
- **URL mode:** `scheme://host/...` for http, https, ftp(s), ws(s), rtsp, rtmp,
  mms, udp. Grouped by domain. Optional scheme filter.
- **Regex mode:** built-in presets (email, IPv4, IPv6, GUID, API key, file path)
  and a custom ECMAScript pattern. Grouped by pattern.

## Safety by design

- Findings are shown as **plain selectable text**. There is **no click-to-open**:
  the tool never opens a URL in a browser.
- **Save as TXT** and **Send to editor** write the file **directly** and **never
  use the clipboard**, so a background download manager (JDownloader and the
  like) cannot pick the links out of the clipboard.
- Only the explicit **Copy selected** button puts anything on the clipboard.
- It never writes to another process, injects code, or opens the OS security
  core; it only reads readable memory of processes the current user may open.

## Build

Needs the MSVC C++ build tools (Visual Studio 2022 or the standalone Build
Tools). From the repo root:

```
pwsh -File build.ps1
```

The result is `bin\URLRipper.exe` (static CRT, `/MT`). A prebuilt copy lives in
`bin\` in this repo. There is also a CMake build (`CMakeLists.txt`) that produces
the same exe and registers the portable-core self-test.

## Usage

Run `URLRipper.exe` with no arguments for the window. Pick a process (or a file),
choose URL or Regex mode, tick the encodings, press **Scan**.

Command line (results are printed as text, or written with `--out`; nothing is
opened):

```
URLRipper.exe --pid 4821
URLRipper.exe --file game.exe --preset email,apikey
URLRipper.exe --folder .\dump --regex "\bAKIA[0-9A-Z]{16}\b" --out keys.txt
URLRipper.exe --help
```

Scanning some processes (higher-integrity ones) needs an elevated instance.

## Layout

- `src/scan_core.hpp` - portable detector (encodings, URL/regex matching,
  de-dup, grouping, sorting). No platform headers, unit-testable anywhere.
- `src/win_process.hpp` - Win32 process enumeration and memory reading.
- `src/file_read.hpp` - file and folder reading.
- `src/main.cpp` - Win32 GUI and the command-line mode.
- `tests/test_scan.cpp` - self-test for the core (`ctest` or build directly).

Author: Andreas Wendorf (Akustikrausch).
