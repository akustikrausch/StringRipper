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

The expanded suites additionally cover absolute offsets, named captures, file selection, relative exclusions, job serialization, SQLite sessions/favorites, session comparison and CLI round trips. Six Release tests and six sanitizer tests passed on Linux. The Win32 GUI and SQLite adapter translation units compile with MinGW; the MSVC build and the native GUI run are below.

## Follow-up audit

- `namedGroups()` took any `(?<` for a named group, so lookbehind `(?<=...)` / `(?<!...)` failed with "named group has no closing >". std::regex has no lookbehind; it now fails on its own terms.
- Both regex engines can give up on a window: libstdc++ and the MSVC STL throw `regex_error` (complexity, and on MSVC a 600/1000-frame stack limit) instead of overflowing the stack. The exception escaped `matchRegex` and killed the whole scan. A window that throws is now skipped. Control run on MSVC 14.44: the pre-fix code aborts the adversarial harness (0xC0000409), the fixed code finishes it in about 14 ms.
- `csvField()` did not neutralize cells starting with `=`, `+`, `-`, `@` or tab, so an export of scanned (attacker-controlled) content could run as a formula in Excel/Sheets (CWE-1236). Those cells get a leading quote now.
- Workspace "Run selected" read the job name with `LB_GETTEXT` into a fixed `wchar_t[256]`. `LB_GETTEXT` has no bound and job names are free text, so a long name overflowed the stack (reproduced with 500 and 4000 characters). The buffer is sized from `LB_GETTEXTLEN` now and the name field is capped at 200 characters.
- The windowed-regex tests were compiled for libstdc++ only. They run on every engine now; only the backreference check stays guarded (libstdc++'s polynomial mode rejects backreferences, MSVC accepts them).

Regression tests for all of it are in `tests/test_scan.cpp`, `tests/test_features.cpp` and `tests/test_workspace.cpp`.

## Verification (MSVC build, native GUI)

Release exe built with `build.ps1` (`cl /O2 /GL /MT`, `/LTCG`, embedded manifest): 1.2.0, static CRT, no msvcrt/vcruntime import. Linux: six ctest tests, ASan+UBSan over all five test binaries, TSan over the driver test. The five test binaries also pass built with MSVC 14.44 (`/O2 /MT`), and the MinGW cross-build compiles.

GUI, run by hand on Windows:

| Area | Status |
| --- | --- |
| Start, everything-on file scan (all decoders, custom regex, all presets) | Passed |
| Pause / resume / cancel | Passed |
| Process scan with live progress | Passed |
| Preset editor: validate, reject, fix, save; backup and recovery checked on disk | Passed |
| Workspace: save/list/run job, incl. the long job name fix | Passed |
| Dashboard open/close | Passed |
| Scan settings: invalid range warns, valid range applies | Passed |
| Live: toggle, interval, one automatic rescan | Passed |
| Adversarial regex harness built with MSVC | Passed |
| Native Export dialog (txt/csv/json/sqlite) | Not run by hand; `exportResults()` and `SessionStore` under it are unit-tested |
| Original crash reproduction | Not run; the crashing process was not available. Covered by the adversarial harness (libstdc++ and MSVC) and a live scan of a real process |
| Code signing | Not done, no certificate |
