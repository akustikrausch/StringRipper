# StringRipper

Small Windows tool for ripping strings out of running processes, files or whole folders. Mostly built because I needed it myself :)

Give it a process and it digs through readable memory looking for URLs or whatever regex you throw at it. Works with ASCII/ANSI/UTF-8, UTF-16 LE/BE and also unwraps one layer of Base64 or hex along the way.

One portable exe. No installer, no DLL mess. It's unsigned for now.

It de-dups the results, can group them by domain/pattern and sort Z-A.

URL mode knows http/https, ftp, ws, rtsp, rtmp, mms, udp etc. I made the URL detector a bit picky on purpose. The host has to look real, so random memory garbage containing `://` doesn't flood the results.

Regex mode has a few presets for the usual stuff: email, IPv4/IPv6, GUIDs, API keys, file paths... or give it your own ECMAScript regex.

Findings stay plain text. No clickable URLs. `Save as TXT` and `Send to editor` write straight to disk and never touch the clipboard. This is intentional... some download managers love watching the clipboard and immediately grabbing every URL they see. `Copy selected` is the only thing that puts anything there.

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

The actual StringRipper side is pretty small: `scan_driver.hpp` throws the work over a pool of `cores - 2`, and `scan_core.hpp` does the detection. URLs use my own scanner, `std::regex` is only used for regex patterns.

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

CLI works too:

```text
StringRipper.exe --pid 4821
StringRipper.exe --file game.exe --preset email,apikey
StringRipper.exe --folder .\dump --regex "\bAKIA[0-9A-Z]{16}\b" --out keys.txt
StringRipper.exe --help
```

Reading a higher-integrity process needs an elevated StringRipper. Windows being Windows :)

## Source layout

- `src/scan_core.hpp` - scanner/detector, no platform stuff, self-tested
- `src/scan_driver.hpp` - worker pool for memory + files
- `src/file_read.hpp` - folder crawling
- `src/main.cpp` - Win32 GUI + CLI
- `tests/` - core/driver tests
- `CODE_STYLE.md` - some rules so the native code doesn't turn into complete spaghetti

Akustikrausch.
