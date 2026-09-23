# StringRipper on macOS — build handoff

This is the handoff for building the macOS side of StringRipper. Read it once
before touching a Mac; it says what already builds, what does not, and exactly
how to produce the two binaries the ticket asks for (x86_64 ≥ 10.15, arm64 ≥ 11.0).

## What is portable, and what is not

- **Portable, builds on macOS today:** the whole detection core
  (`src/scan_core.hpp`), the worker pool and file/folder scanning
  (`src/scan_driver.hpp`, `src/file_read.hpp`), and a command-line front end
  (`src/cli_main.cpp`). This scans **files and folders** — URLs, the regex
  presets (incl. the new `fileurl` download preset), the crap filter, all the
  decoders. It is the same core the Windows build uses; the portable tests
  (`tests/test_scan.cpp`) cover it.
- **Windows-only, NOT ported:** reading another process's memory (that is
  FXChainPlayer's `rip_backend_win32.cpp` behind `IMemoryReader`), and the whole
  Win32 GUI in `src/main.cpp`. `scan_driver.hpp` now hides the process path
  behind `SR_HAVE_RIPPER` (set only when the FXChainPlayer header is present), so
  the core compiles clean without it.

So the macOS deliverable right now is a **CLI for files and folders**. A macOS
GUI and a macOS process-memory reader are a separate, larger project — see the
last section before committing to it.

## Build both slices on your M3 (no Rosetta needed)

The CLI's local session and job store links the macOS system SQLite library.
The universal build script compiles the store adapter into both slices.

Rosetta is only for *running* x86_64 code on Apple Silicon. **Compiling** an
x86_64 slice on an M3 is just a target flag — the macOS SDK carries both slices.
So your M3 + macOS 27 can build everything the ticket wants:

```bash
./build-macos.sh
```

produces, in `dist/mac/`:

- `stringripper-arm64`   — arm64, min macOS 11.0
- `stringripper-x86_64`  — x86_64, min macOS 10.15 (no Metal; it is a CLI)
- `stringripper`         — universal (both slices via `lipo`)

Verify the slices and the min-versions:

```bash
lipo -info dist/mac/stringripper
vtool -show-build dist/mac/stringripper-x86_64   # LC_VERSION_MIN → 10.15
otool -l  dist/mac/stringripper-arm64 | grep -A3 LC_BUILD_VERSION
```

### Separate binaries vs universal

The ticket flags Apple removing Rosetta 2 in a coming macOS. That only affects
running **x86_64-only** apps on Apple Silicon; it does **not** touch a universal
binary — on Apple Silicon the loader runs its native **arm64** slice, on Intel
Macs it runs the x86_64 slice. So:

- **Ship the universal binary** for one download that runs natively everywhere,
  future-proof against the Rosetta removal (Apple Silicon never uses the x86_64
  slice).
- Or ship the two slices **separately** if you want the smallest download per
  arch. Both are produced above; it is a packaging choice, not a code one.

The x86_64 slice at min 10.15 exists purely for **Intel Macs**; it is irrelevant
to Apple Silicon and to the Rosetta question. 10.15 (not 10.13) is the real floor:
`std::filesystem` - used throughout the portable core, not just for directory
listing - needs libc++'s filesystem support, which Apple's SDK only ships from
macOS 10.15 onward; anything older marks `std::filesystem::path` itself
unavailable and the build won't compile.

## Run it

```bash
xattr -dr com.apple.quarantine dist/mac/stringripper   # unsigned: clear Gatekeeper
./dist/mac/stringripper --preset fileurl,apikey ~/Downloads
./dist/mac/stringripper --regex '\.zip$' /some/folder
./dist/mac/stringripper --help
```

## Building remotely instead (GitHub Actions)

`.github/workflows/macos.yml` builds the universal CLI on a GitHub-hosted
`macos-14` (Apple Silicon) runner, smoke-tests it, and uploads
`stringripper-macos` as an artifact. Trigger it from the Actions tab
("Run workflow") or by pushing a `v*` tag. Download the artifact from the run.
This needs no local Mac at all and is the easiest path if you would rather not
build locally.

## Signing & notarization (for giving it to other people)

Unsigned is fine for your own machine (the `xattr` line above). To hand it to
anyone else without Gatekeeper blocking it:

```bash
codesign --force --options runtime --timestamp \
  --sign "Developer ID Application: <YOUR NAME> (<TEAMID>)" dist/mac/stringripper
xcrun notarytool submit dist/mac/stringripper.zip --apple-id <id> --team-id <TEAMID> --wait
xcrun stapler staple dist/mac/stringripper       # only staples bundles/dmg/pkg; for a bare
                                                 # CLI, notarization alone is enough
```

A Developer ID cert needs a paid Apple Developer account. Same story as Windows:
the README says "unsigned for now", and that is fine for the CLI too.

## If you later want the full macOS app (process scanning + GUI)

This is the big piece and is deliberately **not** in this handoff. What it takes:

- **Reading another process's memory** on macOS uses the Mach VM API
  (`task_for_pid` / `mach_vm_read_overwrite` walking `mach_vm_region`). macOS
  locks this down hard: `task_for_pid` on anything you do not own needs the app
  **signed with the `com.apple.security.cs.debugger` entitlement**, and the
  target must not be a hardened/SIP-protected process. In practice you run it
  with `sudo`, or you sign + notarize with that entitlement. There is no
  equivalent of "just open the process as the same user" like on Windows.
- **A GUI**: either a native Cocoa/AppKit port of `main.cpp` (a real rewrite —
  none of the Win32 code carries over), or a small cross-platform toolkit. The
  detection core stays exactly as-is; only the shell is new.

Recommended order if it gets scheduled: (1) land this CLI, (2) add the Mach
reader as a `scan_reader_mac.mm` behind the same idea as `SR_HAVE_RIPPER`, gated
on entitlement/sudo, (3) only then a GUI. Keep it its own milestone.
