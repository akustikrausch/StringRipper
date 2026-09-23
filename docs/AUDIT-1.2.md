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

A native Windows GUI smoke test and MSVC release build remain pending: the host has no detected MSVC toolchain and its MinGW headers lack the audio-meter interface required by the external FXChainPlayer backend. The existing release EXE has not been replaced.
