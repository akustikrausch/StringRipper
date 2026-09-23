# StringRipper

Small Windows tool for ripping strings out of running processes, files or whole folders. 

Give it a process and it digs through readable memory looking for URLs or whatever regex you throw at it. Works with ASCII/ANSI/UTF-8, UTF-16 LE/BE and also unwraps one layer of Base64 or hex along the way.

One portable exe. No installer, no DLL mess. It's unsigned for now.

It deduplicates overlap windows while retaining distinct source locations, groups by domain/pattern and sorts Z-A.

URL mode knows http/https, ftp, ws, rtsp, rtmp, mms, udp etc. I made the URL detector a bit picky on purpose. The host has to look real, so random memory garbage containing `://` doesn't flood the results.

Regex mode has a few presets for the usual stuff: email, IPv4/IPv6, GUIDs, API keys, file paths... or give it your own ECMAScript regex.

Version 1.2 adds user presets. Put `regex-user-presets.ini` beside `StringRipper.exe` and the first preset is loaded automatically at startup. The **User presets...** browser can create, edit, validate, save and activate presets, including decoder and built-in regex-mode switches. Every save writes a temporary file first and keeps the previous settings as `regex-user-presets.ini.bak`; a damaged main file is recovered from that backup automatically.

Four more additions in 1.2:

- **Test sample** in the preset editor runs the selected patterns against example text, one candidate per line. It shows distinct matches grouped by pattern. This tests the patterns directly, without decoding the sample; input is limited to 2048 characters and is not saved in the INI.
- **Export...** offers TXT, CSV and JSON. CSV/JSON include group, value, encoding and source. Exports contain exactly the currently filtered view.
- **New only** compares two complete scans of the same source with the same scan options. It compares group and value, ignoring changed addresses/encodings. The first successful scan establishes a baseline; cancelled, failed or incomplete scans never replace it. Clear resets the comparison. Only the most recent successful baseline is kept in memory.
- **CLI user presets** work on Windows, macOS and Linux: list presets or select one by exact name. Explicit regex/decoder switches override the preset regardless of argument order. The CLI only loads a preset when requested.

The editor preserves unsaved changes until you choose to save or discard them. Builds only install the starter file when no settings file exists. In the INI, backslashes are doubled; `\n` and `\r` encode line breaks. The editor accepts ordinary regex syntax and handles that escaping automatically.

## Workspace in 1.2.0

The **Workspace...** browser saves and reopens scan sessions in a local SQLite database, compares two saved sessions side by side (added, removed, unchanged), and saves/runs named jobs. The default GUI database is `%LOCALAPPDATA%\StringRipper\workspace.sqlite`; results stay on the local machine. Favorite processes or paths can be added and reselected there. The **Dashboard** summarizes findings by pattern, source and encoding.

Each direct ASCII/UTF-16 finding carries its byte offset or memory address, a short surrounding context and any named regex captures such as `(?<version>...)`. Double-click a result for details; right-click it to inspect bytes at the offset, open its source file or favorite that source. Decoded Base64/hex matches do not claim a direct source offset.

**Scan settings...** filters files by include/exclude glob, size and modification date (YYYY-MM-DD), or restricts scanning to a byte/address range. Comma-separated patterns such as `*.txt,*.log` and relative folder patterns such as `logs/*.txt` are supported. **Pause/Resume** stops both producer and workers without losing queued work. **Live** periodically rescans at the entered interval in seconds; the status reports added, removed and unchanged findings. Results are displayed 500 at a time and can be searched by value, pattern, source or encoding. The export dialog can append the filtered view as a SQLite session as well as write TXT/CSV/JSON; structured exports include offsets, context and captures.

Regex presets can now store positive and negative example lines. **Run saved cases** checks every line, while **Add to profile** combines several presets for one scan. Reusable jobs persist the chosen sources, profile, file selection and live interval.

Regex process scans use bounded, overlapping 1024-character windows and return matches up to 512 characters. Regex patterns are limited to 512 bytes. The MinGW/libstdc++ release uses a non-recursive polynomial matcher; backreferences such as `(a)\1` are rejected because they cannot be handled safely by that matcher. These limits protect scans of long printable memory runs from stack overflows.

The release includes a neutral starter file with ticket-ID and semantic-version examples. Each preset uses one ordinary INI section:

```ini
[Regex User Preset: Support ticket IDs]
Description=Find ticket references such as TKT-123456 in text and log files.
Regex=\\bTKT-[0-9]{6}\\b
Positive=TKT-123456
Negative=ABC-123456
Validated=1

ASCII=1
UTF-16=1
HEX=0
BASE64=0

Custom=1
Email=0
IPv4=0
IPv6=0
GUID=0
APIKey=0
Filepath=0
Download=0
```

The result filter narrows by group, value, source or encoding, and only the filtered view is exported. Pagination affects display, not export.

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

The process reader comes from the ripper backend I originally wrote for FXChainPlayer (`src/audio/rip_backend_win32.cpp` through `IMemoryReader`). That part does the memory region walking, integrity handling, image classification and UAC relaunch.

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

CMake works too:

```text
cmake -DFXCHAINPLAYER_DIR=<checkout>
```

## Usage

Run it without arguments if you want the GUI. Pick/filter a process or file, choose URL or Regex mode, select the encodings and hit Scan.

You can also drop files or folders straight onto the window, or straight onto the exe itself (Explorer launches it and it scans them). Several at once is fine, folders get walked recursively. Dropping on the window only sets the source and you still hit Scan; dropping on the exe scans right away. Only one instance runs at a time, a second launch hands its files to the first and bows out, so scans never race.

The process list refreshes itself as programs come and go, and if the process you scanned exits the results clear themselves. Scan progress shows a percent. There's a Clear button, and a Crap filter (on by default in URL mode) that drops placeholder and XML-namespace hosts. Regex mode has a Download preset for partial file URLs ending in .exe/.zip/.dmg/.pkg and the like.

Progress uses two decimal places and counts completed plus explicitly skipped bytes against the planned range; overlap bytes are not counted twice. File sizes and readable process-memory regions are planned in the background first; process scans are limited to the first 2 GiB of eligible memory. A file scan uses the planned size even if the file grows. Cancellation and pause work for files, folders and processes between work chunks.

Audit findings, validation and benchmark instructions are in [docs/AUDIT-1.2.md](docs/AUDIT-1.2.md).

CLI works too:

```text
StringRipper.exe --pid 4821
StringRipper.exe --file game.exe --preset email,apikey
StringRipper.exe --folder .\dump --regex "\bAKIA[0-9A-Z]{16}\b" --out keys.txt
StringRipper.exe --file setup.bin --preset fileurl        # download URLs
StringRipper.exe --folder .\dump --scheme https --no-crap  # keep every host
StringRipper.exe --help
```

Saved presets and structured export (use `stringripper` on macOS/Linux):

```text
StringRipper.exe --list-user-presets
StringRipper.exe --file log.txt --user-preset "Support ticket IDs" --format json --out tickets.json
StringRipper.exe --file log.txt --presets-file C:\Tools\regex-user-presets.ini --user-preset "Semantic versions" --format csv --out versions.csv
```

The portable CLI also supports `--include`, `--exclude`, size/date and byte-range filters, `--db`, `--save-session`, `--open-session`, `--compare-sessions`, `--save-job`, `--run-job`, `--list-jobs`, `--favorite`, `--favorites` and `--format sqlite`. Repeat `--user-preset` to combine patterns. Numeric dates are Unix seconds in the CLI; ranges accept decimal or `0x` hex and have an exclusive end.

Without `--presets-file`, the CLI reads `regex-user-presets.ini` next to the actual executable, independent of the working directory. Missing/invalid files and unknown names fail with exit code 2; a valid scan with no matches returns 1, otherwise 0. The GUI still automatically loads the first preset when its INI exists.

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

The detection core is portable. `build-macos.sh` builds a universal CLI (arm64 min 11.0, x86_64 min 10.15) that scans files and folders; process memory stays Windows-only. Full details, including building both slices on an Apple Silicon Mac and the GitHub Actions route, are in [`docs/MACOS.md`](docs/MACOS.md).

Akustikrausch.
