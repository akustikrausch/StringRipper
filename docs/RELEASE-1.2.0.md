# StringRipper 1.2.0 — release preparation

This release adds local regex user presets with syntax checks, saved positive/negative cases, profile composition and backup-safe INI writes. The starter INI contains only neutral support-ticket and semantic-version examples.

The scan workspace adds precise direct hit offsets and context, named regex captures, pause/resume, live rescan with added/removed/unchanged counts, 500-row pagination, filtering by value/pattern/source/encoding, a dashboard, source favorites, configurable file/date/size/exclusion/range selection, reusable multi-source jobs, SQLite sessions and side-by-side session comparison. TXT/CSV/JSON exports now include finding metadata; SQLite export appends a session.

Architecture: portable detection and workspace domain, scanner/selection application services, SQLite and INI adapters, and Windows/portable CLI presentation adapters. The macOS universal CLI links the system SQLite library; Windows links the bundled amalgamation statically.

Verification: six Release tests and six ASan/UBSan tests pass on Linux, including CLI round trips; the five test binaries also pass built with MSVC. The release exe is an MSVC build (`build.ps1`, static CRT, one file, no DLLs); `build-mingw.sh` still cross-builds a Windows x64 GUI from Linux. It was also run by hand on Windows, see docs/AUDIT-1.2.md for the matrix. The native Export dialog was not run by hand.

Crash fix after local release build: Windows Error Reporting recorded a stack overflow in libstdc++'s recursive regex executor during a process scan. The MinGW build now forces the non-recursive polynomial executor, limits pattern size and scans long printable runs in overlapping windows. Regression tests cover long runs, cross-window offsets, anchors and backreference rejection. Matches longer than 512 characters are intentionally not returned.

Follow-up audit fixed four more things: lookbehind reported as a broken named group, a regex window the engine gives up on killing the whole scan (MSVC and libstdc++ both throw there; that window is skipped now), CSV cells that ran as spreadsheet formulas (CWE-1236), and a stack overflow on very long job names in the Workspace. Details and tests in docs/AUDIT-1.2.md.
