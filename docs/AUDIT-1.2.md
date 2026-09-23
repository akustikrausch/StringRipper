# 1.2 audit

## Correctness fixes

- Progress counts bytes after detector work finishes, excluding overlap. The total comes from a file-size snapshot or a readable-memory-region plan capped at 2 GiB, rather than process working-set estimates.
- Planning runs off the UI thread. Progress has two decimal places, separate planning/finalizing states, and counts completed plus skipped bytes against the planned range. Skipped data is marked separately; the final status reports completion or an incomplete scan.
- File/folder scans honor cancellation; queued work is discarded on cancellation. A running detector call finishes before cancellation takes effect.
- Worker exceptions propagate to the scan result instead of terminating the process. Threads are joined during cleanup.
- Memory limits are enforced exactly. Queue accounting includes the incoming buffer. File growth cannot exceed the planned size.
- Disabling ASCII suppresses direct ASCII findings while still allowing Base64/hex containers when enabled.
- Base64 accumulation uses unsigned arithmetic to avoid signed-shift overflow.
- Preset startup uses the initialized window handle. Long regexes are no longer truncated to 1023 characters when starting a scan.
- Closing the preset editor offers save/discard/cancel; empty selection and validation states are handled explicitly.
- INI loading rejects malformed/duplicate keys, duplicate names, invalid booleans, empty files and missing regex fields. UTF-8 BOMs and significant regex whitespace are preserved.
- Saves replace the INI without deleting it first. A malformed main file cannot overwrite the valid backup. Backup loading also works when the main file is missing.
- Builds seed example presets only when no existing settings file is present.

## Performance

ASCII extraction copies each contiguous run once. Worker count is capped at 16 and the default work chunk is 1 MiB, reducing thread overhead and improving progress granularity. The GUI reuses the compiled detector instead of compiling the same expression twice.

Local Linux/GCC 11.4 measurements, -O2, synthetic 32 MiB input, median of five runs. Both versions must return the same single deduplicated finding. Baseline: scan code at commit 79af2f2.

| Scenario | Before | After |
| --- | ---: | ---: |
| URLs, all decoders | 235.9 MiB/s | 782.4 MiB/s |
| URLs, ASCII only | 336.7 MiB/s | 1101.8 MiB/s |
| Custom regex, ASCII only | 187.6 MiB/s | 502.7 MiB/s |

These are synthetic pipeline measurements, not Windows process-memory throughput guarantees.

After adding per-occurrence offsets, context, profiles, persistence and pagination, the same local Release benchmark measured 703.3 MiB/s (all decoders), 1095.4 MiB/s (ASCII only) and 507.9 MiB/s (custom regex, ASCII only). This is a separate run, not a controlled A/B measurement against the earlier table.

Build the optional benchmark with:
```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target benchmark_scan
./build/benchmark_scan
./build/benchmark_scan ascii
./build/benchmark_scan ascii regex
```

## Verification

Core, preset and driver regression tests cover decoder selection, exact byte caps, overlap accounting, cancellation, unreadable memory, file-size snapshots, preset round trips and backup preservation. AddressSanitizer and UndefinedBehaviorSanitizer were also used. The Win32 translation unit was checked with MinGW.

The expanded suites additionally cover absolute offsets, named captures, file selection, relative exclusions, job serialization, SQLite sessions/favorites, session comparison and CLI round trips. Six Release tests and six sanitizer tests passed on Linux. The updated Win32 GUI and SQLite adapter translation units compiled with MinGW; a native Windows GUI smoke test and MSVC release build are still pending.

## Follow-up audit (lookbehind, scan abort, CSV injection, job-name overflow)

- `namedGroups()` treated any `(?<` as a named-group start, so a lookbehind assertion `(?<=...)` / `(?<!...)` was rejected with "named group has no closing >" instead of failing on its own terms. std::regex still cannot compile lookbehind; the diagnosis is now correct instead of misleading.
- The polynomial regex executor can still throw `regex_error(error_complexity)` against a specific automaton/input pairing inside one window — observed live scanning a real running process. It previously escaped `matchRegex` uncaught and aborted the entire scan through `ScanPool`'s exception propagation. A window that throws is now skipped like a non-matching one instead of failing the whole scan.
- `csvField()` did not neutralize values starting with `=`, `+`, `-`, `@` or a tab, so a CSV export of scanned (attacker-controlled, by construction) content could execute as a formula when opened in Excel/Sheets — CWE-1236. Such fields are now quote-prefixed.
- The Workspace "Run selected" job handler read the selected job name with `LB_GETTEXT` into a fixed `wchar_t[256]`. `LB_GETTEXT` has no length limit of its own, and job names are free-typed text with no cap anywhere on the write path, so a longer name overflowed the stack. The buffer is now sized from `LB_GETTEXTLEN` first; the name field is also capped at 200 characters as defense in depth. Confirmed exploitable pre-fix and fixed against the compiled binary with 500- and 4000-character job names.

All four are regression-tested (`tests/test_scan.cpp`, `tests/test_features.cpp`, `tests/test_workspace.cpp`).

## Verification (MSVC build and native GUI)

A fresh MSVC release build now exists (`build.ps1`: `cl /O2 /GL /MT`, `/link /LTCG /MANIFEST:EMBED`), FileVersion/ProductVersion 1.2.0, statically linked CRT (no msvcrt/vcruntime import), confirmed against the compiled exe. Six Release ctest tests, the MinGW cross-build (stack-overflow and lookbehind regressions), and a manual ASan+UBSan+TSan pass over all five test binaries all pass clean against the current source.

Interactive native GUI test, on Windows:

| Area | Status |
| --- | --- |
| Start, everything-on file scan (all decoders, custom regex, all presets) | Passed |
| Pause / resume / cancel | Passed |
| Process scan with live progress | Passed |
| Preset editor: validate, reject, fix, save; backup/recovery verified on disk | Passed |
| Workspace: save/list/run job, incl. the job-name overflow fix | Passed |
| Dashboard open/close | Passed |
| Scan Settings: reject invalid range (warning shown), accept once fixed | Passed |
| Live/monitor toggle, interval, one confirmed auto-rescan | Passed |
| Native Export dialog (txt/csv/json/sqlite) | Not executed — system common dialog, not automatable the same way; `exportResults()`/`SessionStore` beneath it are unit-tested |
| LogiTune reproduction specifically | Not executed — LogiTune unavailable in this environment; the crash path is instead covered by the adversarial-regex harness and a live scan of a real running process |
| Code signing / notarization | Blocked — requires separate authorization |
| Push / GitHub release | Blocked — requires separate authorization |

The existing release EXE has been replaced.
