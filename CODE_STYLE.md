# Native code style

The C/C++ reads like a veteran demoscene coder wrote it. Non-negotiable.

## Comments
- No explanatory comments. The code speaks for itself.
- No bug-fix or issue-tracking comments (`FIX #3`, `matches JS`, `restored`).
- Terse section dividers are fine, and rare: `/* scan */`, `/*--- pool ---*/`.
- If a comment wants to explain WHY, restructure so the code makes it obvious.

## Error handling
- No error dialogs or graceful-degradation clutter in the hot path. A tool has
  exactly the UI it needs: the About box, and the two prompts that change what
  the user does next (pattern error, elevation). Nothing else pops up.
- No defensive bounds checks that never fire. Trust the data.

## Style
- Dense, compact. Related assignments share a line: `r.base=b; r.size=s;`.
- Bitwise where it reads clean: `& 15`, `>> 1`, `& 1`.
- Short locals: `v`, `n`, `f`. Struct members may be longer, they cross files.
- No unused includes. No dead code. `static` everything file-local.

## Architecture
- Minimal file count. Add to an existing file before making a new one.
- No abstraction for its own sake. Three plain lines beat a premature helper.

## Commits
- Terse, lowercase, one line. No body, no ticket refs, no tool credits.
  `lto, terse about` not a paragraph.
- No issue tracker on this repo. No tickets, no AI attribution, anywhere.

## Look
- Dark or nothing. Anything the common controls paint light -- combo field,
  list header, push buttons, scrollbars -- is drawn here or re-themed.
- Dim text stays at 7:1 on the background. Sample the pixels, don't eyeball it.
- Every metric goes through `S()`. The window is per-monitor DPI aware, so no
  raw pixel constants in the layout.

## Performance
- FXChainPlayer rule, and it holds here: performance is king. Paint and scan
  paths stay O(visible) or O(work), never O(everything). 20k groups repaint
  from a binary search, not a sweep.
- Measure both sides. A number beats an adjective.

## Size and build
- No crinkler, no 32 KB target: this is a native Win32 tool, not an intro. It
  keeps the static C runtime because it uses `<regex>`, `<thread>`,
  `<filesystem>`.
- Still lean: LTO on (`/GL /LTCG`), `/O2 /Gy`, link `/OPT:REF /OPT:ICF`, one exe,
  no DLLs. Manifest is embedded (`/MANIFEST:EMBED`): the bare exe needs
  comctl32 v6 for the grouped list.
- The reader is compiled from FXChainPlayer, not vendored (see README).
- One version, `src/version.h`. main.cpp and the .rc read it, nothing else
  hardcodes a version string.
