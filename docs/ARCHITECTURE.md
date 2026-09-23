# Architecture

StringRipper keeps detection independent of Win32, filesystems and SQLite. Workspace rules use standard filesystem paths but no Win32 or SQLite APIs. The dependency direction is:

~~~text
Win32 GUI / Windows CLI / portable CLI
    -> scan application services (scan_service, scan_driver, result_tools)
    -> domain rules (scan_core, workspace)

filesystem input -> scan_service -> scan_driver
FXChainPlayer memory reader -> process_scan_win32 -> scan_driver
SQLite session_store -> workspace domain types
INI regex_presets -> scan_core options
~~~

The scanner receives byte windows and emits findings with stable source identity, optional absolute offsets, short context and named captures. It neither opens processes nor reads files. The scan driver owns bounded worker queues, cancellation, pause and byte accounting. The scan service composes file selection, progress planning and file reads; both CLIs and the Win32 GUI use it. The Win32 executable adapts controls and timers, while the process adapter opens FXChainPlayer readers. Process memory remains Windows-specific.

The workspace domain defines scan jobs, sessions and their comparison without persistence concerns. The SQLite adapter implements local storage with prepared statements and transactional session writes. The GUI locates its database under LocalAppData; CLI callers choose a path with --db. The user-preset INI is separate and retains its atomic save plus .bak recovery behavior.

Tests target the domain and adapters separately: detector/driver/preset/result/workspace unit suites, a CLI end-to-end suite, and an optional synthetic throughput benchmark. The Windows GUI translation unit is cross-compiled on Linux, but native GUI interaction and MSVC release packaging require a Windows host.
