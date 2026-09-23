# StringRipper 1.2.0 — release preparation

This release adds local regex user presets with syntax checks, saved positive/negative cases, profile composition and backup-safe INI writes. The starter INI contains only neutral support-ticket and semantic-version examples.

The scan workspace adds precise direct hit offsets and context, named regex captures, pause/resume, live rescan with added/removed/unchanged counts, 500-row pagination, filtering by value/pattern/source/encoding, a dashboard, source favorites, configurable file/date/size/exclusion/range selection, reusable multi-source jobs, SQLite sessions and side-by-side session comparison. TXT/CSV/JSON exports now include finding metadata; SQLite export appends a session.

Architecture: portable detection and workspace domain, scanner/selection application services, SQLite and INI adapters, and Windows/portable CLI presentation adapters. The macOS universal CLI links the system SQLite library; Windows links the bundled amalgamation statically.

Verification: six Release tests and six ASan/UBSan tests pass on Linux, including CLI round trips. The Windows x64 GUI builds with MinGW into a single portable executable. A native interactive Windows GUI test is still required before publishing a GitHub release.

Crash fix after local release build: Windows Error Reporting recorded a stack overflow in libstdc++'s recursive regex executor during a process scan. The MinGW build now forces the non-recursive polynomial executor, limits pattern size and scans long printable runs in overlapping windows. Regression tests cover long runs, cross-window offsets, anchors and backreference rejection. Matches longer than 512 characters are intentionally not returned.
