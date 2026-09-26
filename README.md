# StringRipper

Small Windows tool for ripping strings out of running processes, files or whole folders.

Give it a process and it digs through readable memory looking for URLs or whatever regex you throw at it. Works with ASCII/ANSI/UTF-8, UTF-16 LE/BE and also unwraps one layer of Base64, hex or escaping along the way. So `https:\/\/`, `https%3A%2F%2F` and `\u002F` from JSON blobs and query strings come out as plain URLs.

Umlauts and other non-ASCII letters stay inside the string, `C:\Users\Jürgen\...` comes out whole instead of cut at the ü. UTF-8, ANSI and UTF-16 alike. A lone non-ASCII word with nothing ASCII around it is still missed, that keeps random memory from turning into fake text.

**All instances** scans every process with the selected name in one go. Browsers like to spawn twenty of them. Each hit then says which pid it came from.

Memory hits also say where they sat: `xul.dll .rdata`, `mapped foo.dat`, `stack`, `heap` or `private`. It's part of the source, so the filter box finds them. `heap` means the process heaps' base segments, everything else unnamed stays `private`.

One portable exe. No installer, no DLL mess. It's unsigned for now.

It checks GitHub for a newer version on startup (you get asked once, on first run) and can download and install it in place. Your presets and saved scans are kept. The check is off if you say no; a manual one sits behind the About button.

Dedups overlap windows (hits from different sources stay separate), groups by domain or pattern, sorts Z-A.

URL mode knows http/https, ftp, ws, rtsp, rtmp, mms, udp etc. I made the URL detector a bit picky on purpose. The host has to look real, so random memory garbage containing `://` doesn't flood the results.

Regex mode has presets for the usual stuff: email, IPv4/IPv6, GUIDs, API keys, file paths, download URLs... or give it your own ECMAScript regex.

## User presets

Put `regex-user-presets.ini` next to the exe and the first preset loads at startup. **User presets...** creates, edits, validates and saves them, decoder and built-in switches included. Unsaved edits stay until you save or discard. The editor resizes and maximizes; while it's open the main window waits in the taskbar and comes back when you close it.

Presets can carry example lines. **Test sample** runs the patterns against pasted text (2048 chars, not saved), **Run saved cases** checks every saved line, **Add to profile** stacks presets into one scan.

Every save goes to a temp file first and the old file stays as `regex-user-presets.ini.bak`. A broken ini gets restored from it. Builds only drop the starter file when there is none.

One section per preset, only `Regex` is required. Backslashes are doubled in the file, `\n` and `\r` stand for line breaks. The editor does the escaping for you.

```ini
[Regex User Preset: Support ticket IDs]
Description=Find ticket references such as TKT-123456.
Regex=\\bTKT-[0-9]{6}\\b
Positive=TKT-123456
Negative=ABC-123456
ASCII=1
UTF-16=1
HEX=0
BASE64=0
ESCAPED=1
Custom=1
```

`Email`, `IPv4`, `IPv6`, `GUID`, `APIKey`, `Filepath` and `Download` switch the built-in patterns on (1) or off (0).

## Workspace

**Workspace...** keeps scan sessions in a local SQLite file (`%LOCALAPPDATA%\StringRipper\workspace.sqlite`), compares two sessions side by side (added, removed, unchanged) and saves named jobs: sources, profile, file filter, live interval. Favorite processes and paths live there too, and so does the ignore list. **Dashboard** counts findings by pattern, source and encoding. Nothing leaves your machine.

Direct ASCII/UTF-16 hits and unescaped ones carry their file offset or memory address, a bit of context and named captures like `(?<version>...)`. Double-click a hit for details, right-click to inspect the bytes, open the source file or favorite the source. Decoded Base64/hex hits don't claim an offset.

## Ignore list

Right-click a hit and ignore its host or just that value, gone from the list. The **Ignore list** chip switches it on and off, the status line counts what it hides. Nothing gets deleted, exports just follow what you see. **Edit ignore list...** (same menu) takes one rule per line:

```text
microsoft.com      that host and all its subdomains
*telemetry*        values matching the pattern, * and ?
=https://x.y/z     exactly this value
# comment
```

Case doesn't matter. The CLI takes the same rules with `--ignore`, repeatable.

**Scan settings...** filters files by include/exclude glob (`*.txt,*.log`, `logs/*.txt`), size, modified date (YYYY-MM-DD) or byte/address range. **Pause/Resume** freezes producer and workers without losing queued work. **Live** rescans every N seconds and tells you what got added, removed, unchanged. **New only** shows what appeared since the last complete scan of the same source with the same options. Cancelled or failed scans never replace that baseline, Clear resets it.

Results show 500 at a time. Filter by value, pattern, source or encoding.

## Regex limits

Regex scans run in overlapping 1024-char windows. Hits over 512 chars aren't returned, patterns over 512 bytes are refused. When the regex engine gives up on a window (complexity or stack limit) that window is skipped and the scan goes on. A nasty pattern can miss hits, it can't take the scan down. libstdc++ builds (MinGW, Linux) force its non-recursive matcher, which also rejects backreferences like `(a)\1`. The MSVC build accepts them.

## Export

**Export...** writes TXT, CSV, JSON or appends a SQLite session, and only what the filter currently shows. Paging is display only. CSV/JSON carry offsets, context and captures. CSV cells starting with `=`, `+`, `-` or `@` get a leading quote so Excel doesn't run them.

Findings stay plain text. No clickable URLs. `Export...` and `Send to editor` write straight to disk and never touch the clipboard. This is intentional... some download managers love watching the clipboard and immediately grabbing every URL they see. `Copy selected` is the only thing that puts anything there.

It only reads memory the current user is allowed to open. No injection, no writing into other processes, no messing around with the Windows security stuff.

Export looks basically like this:

```text
example.com (3)
https://example.com/foo
https://example.com/bar
https://example.com/baz
```

## Some FXChainPlayer DNA inside

The process reader comes from the ripper backend I originally wrote for FXChainPlayer (`src/audio/rip_backend_win32.cpp` through `IMemoryReader`). That part does the memory region walking, integrity handling and image classification.

It gets compiled from an FXChainPlayer checkout, it's not copied into this repo.

The actual StringRipper side is pretty small: `scan_driver.hpp` throws the work over a pool of `cores - 2` (at least one, capped at 16), and `scan_core.hpp` does the detection. URLs use my own scanner, `std::regex` is only used for regex patterns.

On my 32 core machine I currently get around 277 MB/s scanning URLs and ~37 MB/s with regex. Good enough for ripping through some rather stupidly large processes :)

## Build

You need MSVC C++ build tools and an FXChainPlayer checkout.

`FXCHAINPLAYER_DIR` points to that checkout. Default is `..\VST-Player`.

```powershell
pwsh -File build.ps1
```

Result:

```text
bin\StringRipper.exe
```

Static CRT + LTO. There's also a prebuilt exe in `bin\`.

No MSVC? `build-mingw.sh` cross-builds from Linux. CMake works too:

```text
cmake -DFXCHAINPLAYER_DIR=<checkout>
```

Tests: `cmake -S . -B build && cmake --build build && ctest --test-dir build`.

## Usage

Run it without arguments for the GUI. Pick or filter a process or file, choose URL or Regex mode, tick the encodings and hit Scan.

Drop files or folders on the window or straight on the exe. Several at once is fine, folders get walked. On the window it only sets the source and you hit Scan, on the exe it scans right away. Only one instance runs, a second launch hands its files to the first and bows out, so scans never race.

The process list follows programs as they come and go, and if the process you scanned exits the results clear themselves (with All instances: once the last one is gone). Progress shows a percent with two decimals, against a plan made up front: file sizes, or the readable memory regions of a process (first 2 GiB). Pause and Cancel take effect between work chunks. Crap filter (on by default in URL mode) drops placeholder and XML-namespace hosts. The Download preset catches partial URLs ending in .exe/.zip/.dmg/.pkg and the like.

Audit notes, tests and benchmark instructions are in [docs/AUDIT-1.2.md](docs/AUDIT-1.2.md).

CLI works too:

```text
StringRipper.exe --pid 4821
StringRipper.exe --name firefox.exe --ignore mozilla.org   # every instance, minus the noise
StringRipper.exe --file game.exe --preset email,apikey
StringRipper.exe --folder .\dump --regex "\bAKIA[0-9A-Z]{16}\b" --out keys.txt
StringRipper.exe --file setup.bin --preset fileurl        # download URLs
StringRipper.exe --folder .\dump --scheme https --no-crap  # keep every host
StringRipper.exe --help
```

Saved presets and structured output (`stringripper` on macOS/Linux):

```text
StringRipper.exe --list-user-presets
StringRipper.exe --file log.txt --user-preset "Support ticket IDs" --format json --out tickets.json
StringRipper.exe --file log.txt --presets-file C:\Tools\regex-user-presets.ini --user-preset "Semantic versions" --format csv --out versions.csv
```

Also: `--no-escaped`, `--ignore`, `--include`, `--exclude`, size/date/range filters, `--db`, `--save-session`, `--open-session`, `--compare-sessions`, `--save-job`, `--run-job`, `--list-jobs`, `--favorite`, `--favorites` and `--format sqlite`. Repeat `--user-preset` to stack patterns. Dates are Unix seconds, ranges take decimal or `0x` hex with an exclusive end. Explicit regex/decoder switches beat the preset, whatever the order.

Without `--presets-file` it reads `regex-user-presets.ini` next to the executable, not from the working directory. Exit code 0 hits, 1 no hits, 2 error (bad file, unknown preset name...).

Reading a higher-integrity process needs an elevated StringRipper. Windows being Windows :) Drag and drop keeps working when it runs elevated, the drop messages are let through on purpose.

The exe asks for nothing at startup, it runs as whoever started it (the manifest is `asInvoker`, on purpose). When a target needs more than that - a process running higher, or files you are not allowed to read - it says so and asks you to close it and start it again as administrator yourself (right-click the exe, Run as administrator). It does not silently relaunch itself. When it is running elevated the title says `[admin]`.

## Source layout

- `src/scan_core.hpp` - scanner/detector, no platform stuff, self-tested
- `src/regex_presets.hpp` - portable user-preset parser, writer and backup save
- `src/result_tools.hpp` - structured exports and scan comparison
- `src/workspace.hpp` - scan jobs, file selection and session comparison
- `src/session_store.hpp/.cpp` - SQLite persistence adapter
- `src/scan_driver.hpp` - worker pool for memory + files
- `src/scan_service.hpp` - shared file-scan use case for GUI and CLI
- `src/process_scan_win32.hpp` - Windows process-reader adapter
- `src/file_read.hpp` - folder crawling
- `src/main.cpp` - Win32 GUI + CLI
- `src/cli_main.cpp` - portable CLI for macOS/Linux (files/folders, no process reader)
- `src/StringRipper.rc`, `src/version.h`, `src/StringRipper.ico` - icon + version info
- `tests/` - core/driver tests
- `docs/MACOS.md` - how the macOS build works and how to build it
- `docs/ARCHITECTURE.md` - dependency boundaries and workspace design
- `CODE_STYLE.md` - some rules so the native code doesn't turn into complete spaghetti

## macOS / Linux

CLI only: files and folders, no process reader. Same flags as the Windows CLI, minus `--pid` and `--name`. `build-macos.sh` makes arm64 (11.0+), x86_64 (10.15+) and a universal binary, and a GitHub Actions workflow does the same on a `v*` tag. Details, incl. building both slices on an Apple Silicon Mac, are in [`docs/MACOS.md`](docs/MACOS.md).

Akustikrausch.
