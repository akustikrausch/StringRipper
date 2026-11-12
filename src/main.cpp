/* StringRipper: URLs and regex out of a process or files. Win32 GUI + CLI.
   reader = FXChainPlayer's ripBackend(), scan = the pool in scan_driver.hpp. */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <shlobj.h>
#include <ole2.h>
#include <richedit.h>
#include <dbghelp.h>
#include <dwmapi.h>
#include <uxtheme.h>
#include <windowsx.h>
#include <pdh.h>
#include <pdhmsg.h>
#include <psapi.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

#include "scan_core.hpp"
#include "path_handoff.hpp"
#include "path_encoding.hpp"
#include "cli_args.hpp"
#include "regex_presets.hpp"
#include "result_tools.hpp"
#include "scan_driver.hpp"
#include "file_read.hpp"
#include "scan_service.hpp"
#include "process_scan_win32.hpp"
#include "process_guard_win32.hpp"
#include "session_store.hpp"
#include "update.hpp"
#include "audio/rip_backend.h"
#include "version.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "pdh.lib")
#pragma comment(lib, "uxtheme.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "uuid.lib")
#pragma comment(linker, "\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#ifndef STRINGRIPPER_VERSION
#define STRINGRIPPER_VERSION SR_VER_STR
#endif
#ifndef STRINGRIPPER_BUILD
#define STRINGRIPPER_BUILD 0
#endif
#define UR_STR2(x) #x
#define UR_STR(x) UR_STR2(x)

// ---------------------------------------------------------------- utf helpers

static std::string narrow(const wchar_t* w) {
    if (!w) return {};
    int n = ::WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return {};
    std::string s(static_cast<std::size_t>(n), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), n, nullptr, nullptr);
    s.resize(static_cast<std::size_t>(n - 1));
    return s;
}
static std::wstring widen(const std::string& s) {
    if (s.empty()) return {};
    int n = ::MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w(static_cast<std::size_t>(n), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), w.data(), n);
    return w;
}

static std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return char(std::tolower(c)); });
    return s;
}

// ---------------------------------------------------------------- shared text

static bool writeTextFile(const std::wstring& path, const std::string& text) {
    std::ofstream f(std::filesystem::path(path), std::ios::binary | std::ios::trunc);
    if (!f) return false;
    f.write(text.data(), static_cast<std::streamsize>(text.size()));
    return static_cast<bool>(f);
}

static std::vector<std::string> splitCsv(const std::string& s) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) { if (c == ',') { if (!cur.empty()) out.push_back(cur); cur.clear(); } else cur.push_back(c); }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

static bool elevated() {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return false;
    TOKEN_ELEVATION e{};
    DWORD n = 0;
    bool up = GetTokenInformation(tok, TokenElevation, &e, sizeof(e), &n) && e.TokenIsElevated;
    CloseHandle(tok);
    return up;
}

// ---------------------------------------------------------------- CLI

static int runCli(int argc, wchar_t** argv) {
    UINT cp = 0;
    if (::AttachConsole(ATTACH_PARENT_PROCESS)) {
        FILE* f = nullptr;
        freopen_s(&f, "CONOUT$", "w", stdout);
        freopen_s(&f, "CONOUT$", "w", stderr);
        cp = GetConsoleOutputCP();
        SetConsoleOutputCP(CP_UTF8);                  // findings are UTF-8; hand the shell its code page back
    }
    struct RestoreCp { UINT cp; ~RestoreCp() { if (cp) { std::fflush(stdout); std::fflush(stderr); SetConsoleOutputCP(cp); } } } restore{cp};
    ur::CliArgs cli;
    try {
        std::vector<std::string> args;
        for (int i = 1; i < argc; ++i) args.push_back(narrow(argv[i]));
        cli = ur::parseCliArgs(args, ur::presetCli(args, ur::executablePresets(argv[0])), true);
    } catch (const std::exception& e) { std::fprintf(stderr, "error: %s\n", e.what()); return 2; }
    auto& o = cli.options;
    auto& inputs = cli.inputs;
    auto& selection = cli.selection;
    uint32_t pid = cli.pid;
    std::string name = cli.name;
    const auto& format = cli.format;
    if (cli.preset.list && !cli.help) {
        for (const auto& p : cli.preset.presets) std::printf("%s\n", p.name.c_str());
        return 0;
    }

    if (cli.help || (inputs.empty() && pid == 0 && name.empty() && cli.runJob.empty() &&
                     !cli.listJobs && !cli.listFavorites && cli.favorite.empty() &&
                     !cli.openSession && !cli.compareA)) {
        std::printf(
            "StringRipper " STRINGRIPPER_VERSION " - extract URLs or regex matches from processes and files.\n\n"
            "Usage:\n"
            "  StringRipper.exe --pid N            [options]   scan a running process\n"
            "  StringRipper.exe --name APP.exe     [options]   scan every running instance of it\n"
            "  StringRipper.exe --file PATH ...    [options]   scan files\n"
            "  StringRipper.exe --folder PATH ...  [options]   scan a folder (recursive)\n\n"
            "Options:\n"
            "  --regex PAT      regex mode with a custom ECMAScript pattern\n"
            "  --preset IDS     regex presets: email,ipv4,ipv6,guid,apikey,filepath,fileurl\n"
            "  --scheme LIST    URL mode: only these schemes (e.g. http,https)\n"
            "  --icase          case-insensitive matching\n"
            "  --no-ascii --no-utf16 --no-base64 --no-hex --no-escaped   turn off a decoder\n"
            "  --ignore RULE    hide a host (and its subdomains), a *glob* or =exact value; repeatable\n"
            "  --out FILE       write results to FILE (never uses the clipboard)\n\n"
            "  --format TYPE    txt (default), csv, json or sqlite\n"
            "  --include GLOBS --exclude GLOBS  file and folder patterns\n"
            "  --min-size N --max-size N  file size filter in bytes\n"
            "  --modified-after UNIX --modified-before UNIX  file date filter\n"
            "  --range-start N --range-end N  byte range, end exclusive\n"
            "  --db FILE --save-session NAME --open-session ID\n"
            "  --compare-sessions ID1 ID2  show added and removed results\n"
            "  --save-job NAME --run-job NAME --list-jobs  reusable scan jobs\n"
            "  --favorite PATH --favorites  mark or list favorite sources\n"
            "  --user-preset NAME       load a saved regex user preset\n"
            "  --list-user-presets      list saved preset names and exit\n"
            "  --presets-file PATH      INI location (default: next to executable)\n\n"
            "Runs as the invoking user; start elevated yourself if a target needs it.\n\n"
            "Reading a process reuses FXChainPlayer's ripper backend; scanning is multi-threaded.\n");
        return cli.help ? 0 : 2;
    }

    try {
        if (cli.listJobs || cli.listFavorites || !cli.favorite.empty() || cli.openSession ||
            cli.compareA || !cli.runJob.empty()) {
            ur::SessionStore db(cli.dbFile);
            if (cli.listJobs) { for (const auto& job : db.listJobs()) std::puts(job.c_str()); return 0; }
            if (cli.listFavorites) { for (const auto& item : db.favorites("source")) std::puts(item.c_str()); return 0; }
            if (!cli.favorite.empty()) { db.setFavorite("source", cli.favorite, true); return 0; }
            if (cli.openSession) {
                const auto text = ur::exportResults(db.loadSession(cli.openSession).groups,
                                                    format == "sqlite" ? "txt" : format);
                std::fwrite(text.data(), 1, text.size(), stdout); return 0;
            }
            if (cli.compareA) {
                const auto delta = ur::compareSessions(db.loadSession(cli.compareA).groups,
                                                       db.loadSession(cli.compareB).groups);
                const auto text = "Added:\n" + ur::exportResults(delta.added, "txt") +
                                  "\nRemoved:\n" + ur::exportResults(delta.removed, "txt");
                std::fwrite(text.data(), 1, text.size(), stdout); return 0;
            }
            auto job = db.loadJob(cli.runJob);
            if (!job) throw std::runtime_error("unknown job: " + cli.runJob);
            o = job->options; selection = job->files; inputs = job->sources; pid = job->pid;
            if (inputs.empty()) {
                if (job->processName.empty()) throw std::runtime_error("Process job has no name; save it again");
                std::vector<std::pair<uint32_t, std::string>> active;
                for (const auto& process : fxchain::ripBackend().enumerate())
                    active.emplace_back(process.pid, process.name);
                auto resolved = ur::resolveProcessJob(*job, active);
                if (!resolved) throw std::runtime_error("Process is not running: " + job->processName);
                pid = *resolved; name.clear();
            }
        }
    } catch (const std::exception& e) { std::fprintf(stderr, "error: %s\n", e.what()); return 2; }

    if (!cli.jobName.empty()) {
        try {
            ur::SessionStore db(cli.dbFile);
            ur::ScanJob job{cli.jobName, inputs, pid, o, selection, 0};
            if (inputs.empty()) {
                job.processName = name;
                if (job.processName.empty()) for (const auto& process : fxchain::ripBackend().enumerate())
                    if (process.pid == pid) { job.processName = process.name; break; }
                if (job.processName.empty()) throw std::runtime_error("Process is not running");
            }
            db.saveJob(job);
        } catch (const std::exception& e) { std::fprintf(stderr, "error: %s\n", e.what()); return 2; }
    }

    std::unique_ptr<ur::Detector> det;
    try { det = std::make_unique<ur::Detector>(o); }
    catch (const ur::RegexError& e) { std::fprintf(stderr, "error: %s\n", e.what()); return 2; }

    std::vector<ur::Group> groups;
    if (!name.empty()) {
        std::vector<uint32_t> pids;
        for (const auto& p : fxchain::ripBackend().enumerate())
            if (_stricmp(p.name.c_str(), name.c_str()) == 0 || _stricmp(p.name.c_str(), (name + ".exe").c_str()) == 0)
                pids.push_back(p.pid);
        if (pids.empty()) { std::fprintf(stderr, "error: no running process named %s\n", name.c_str()); return 2; }
        auto scan = ur::scanProcesses(*det, pids, true, {});
        if (!scan.opened) {
            std::fprintf(stderr, "error: cannot open %s%s\n", name.c_str(),
                         scan.needsElevation ? " (needs elevation: run as administrator)" : "");
            return 2;
        }
        if (scan.denied) std::fprintf(stderr, "note: %zu of %zu instances could not be opened\n", scan.denied, pids.size());
        groups = std::move(scan.groups);
    } else if (pid) {
        bool denied = false, needsElev = false, fdenied = false;
        groups = ur::scanProcess(*det, pid, {}, denied, needsElev);
        if (denied) {
            std::fprintf(stderr, "error: cannot open pid %lu%s\n", (unsigned long)pid,
                         needsElev ? " (needs elevation: run as administrator)" : "");
            return 2;
        }
    } else {
        bool fdenied = false;
        groups = ur::scanPaths(*det, inputs, &fdenied, nullptr, {}, selection);
        if (fdenied) std::fprintf(stderr, "note: some of that could not be read; try an elevated shell\n");
    }
    ur::resolveDownloadHosts(groups);
    if (!cli.ignore.empty()) groups = ur::filterIgnored(groups, ur::IgnoreRules::parse(cli.ignore));

    if (format == "sqlite" || !cli.sessionName.empty()) {
        try {
            ur::SessionStore db(format == "sqlite" && !cli.outFile.empty() ? cli.outFile : cli.dbFile);
            std::string source = pid ? "pid:" + std::to_string(pid) : !name.empty() ? "name:" + name : "";
            for (const auto& input : inputs) {
                if (!source.empty()) source += "; ";
                source += ur::pathUtf8(input);
            }
            const auto id = db.saveSession({0, cli.sessionName.empty() ? "Scan" : cli.sessionName,
                                            source, "", groups});
            std::printf("saved %zu findings as session %lld\n", ur::countFindings(groups),
                        static_cast<long long>(id));
        } catch (const std::exception& e) { std::fprintf(stderr, "error: %s\n", e.what()); return 2; }
        if (format == "sqlite") return 0;
    }

    std::string text = ur::exportResults(groups, format);
    if (!cli.outFile.empty()) {
        if (!writeTextFile(cli.outFile.wstring(), text)) { std::fprintf(stderr, "error: cannot write output file\n"); return 2; }
        std::printf("wrote %zu results to %S\n", ur::countFindings(groups), cli.outFile.c_str());
    } else {
        std::fwrite(text.data(), 1, text.size(), stdout);
    }
    return ur::countFindings(groups) ? 0 : 1;
}

// ---------------------------------------------------------------- GUI

namespace {

enum : int {
    ID_SEARCH = 1000, ID_SOURCE, ID_REFRESH, ID_FILE, ID_MODE_URL, ID_MODE_REGEX,
    ID_ENC_ASCII, ID_ENC_UTF16, ID_ENC_B64, ID_ENC_HEX,
    ID_P_EMAIL, ID_P_IPV4, ID_P_IPV6, ID_P_GUID, ID_P_APIKEY, ID_P_PATH,
    ID_CUSTOM, ID_SCAN, ID_CANCEL, ID_RESULTS, ID_COPY, ID_SAVE, ID_EDITOR, ID_ABOUT, ID_FILTER,
    ID_P_DL, ID_CRAP, ID_CLEAR, ID_PRESETS, ID_NEW_ONLY, ID_PAUSE, ID_PAGE_PREV, ID_PAGE_NEXT,
    ID_WORKSPACE, ID_MONITOR, ID_MONITOR_INTERVAL, ID_SCAN_SETTINGS, ID_DASHBOARD,
    ID_ENC_ESC, ID_ALL_INSTANCES, ID_IGNORE, ID_PRESET_PICK, ID_DUMP, ID_KILL
};
constexpr UINT WM_APP_DONE = WM_APP + 1;
constexpr UINT WM_APP_UPDATE_FOUND = WM_APP + 2;   // background check found a newer version
constexpr UINT WM_APP_UPDATE_PROGRESS = WM_APP + 3; // wParam = percent, download running
constexpr UINT WM_APP_UPDATE_DONE = WM_APP + 4;     // wParam: 1 = ready to relaunch, 0 = failed (lParam = wchar_t* msg)
constexpr UINT WM_APP_UPDATE_UPTODATE = WM_APP + 5; // manual check: nothing newer
constexpr UINT WM_APP_DUMP_DONE = WM_APP + 6;      // wParam: 1 = written, lParam = error code
constexpr UINT_PTR TIMER_PROGRESS = 1;
constexpr UINT_PTR TIMER_PROCS = 2;
constexpr UINT_PTR TIMER_MONITOR = 3;
constexpr UINT_PTR TIMER_LOAD = 4;
constexpr ULONG_PTR kDropMagic = 0x52495050;   /* 'RIPP', dropped-path handoff */

/* palette: URL Ripper design canvas tokens */
const COLORREF kBg = RGB(0x12, 0x12, 0x1A);
const COLORREF kBg2 = RGB(0x1A, 0x1A, 0x24);
const COLORREF kBg3 = RGB(0x22, 0x22, 0x2E);
const COLORREF kCard = RGB(0x16, 0x1C, 0x28);
const COLORREF kText = RGB(0xE8, 0xE8, 0xF0);
const COLORREF kText2 = RGB(0x98, 0x98, 0xB0);
const COLORREF kText3 = RGB(0x78, 0x78, 0xA0);
const COLORREF kAccent = RGB(0x6D, 0x5F, 0xE8);
const COLORREF kAccentHot = RGB(0x7D, 0x70, 0xF0);
const COLORREF kAccent2 = RGB(0x94, 0xA3, 0xFF);
const COLORREF kAccentMuted = RGB(0x22, 0x21, 0x38);
const COLORREF kBSub = RGB(0x2A, 0x2A, 0x38);
const COLORREF kBDef = RGB(0x36, 0x36, 0x48);
const COLORREF kBFoc = RGB(0x4A, 0x4A, 0x62);

HWND g_main = nullptr;
HWND g_secSource, g_search, g_source, g_refresh, g_file, g_settingsButton, g_srcInfo;
HWND g_secFind, g_modeUrl, g_modeRegex, g_urlHint;
HWND g_presetLabel, g_pEmail, g_pIpv4, g_pIpv6, g_pGuid, g_pApi, g_pPath, g_pDl, g_customLabel, g_custom, g_presets;
HWND g_crap;
HWND g_secDecode, g_ascii, g_utf16, g_b64, g_hex, g_esc;
HWND g_scan, g_pause, g_cancel, g_monitor, g_monitorInterval, g_status;
HWND g_secResults, g_filter, g_results, g_copy, g_save, g_editor, g_clear, g_about;
HWND g_pagePrev, g_pageNext, g_pageLabel, g_workspace, g_dashboard;
HWND g_newOnly, g_allInst, g_ignoreChip, g_presetPick, g_dump, g_kill;
std::thread g_dumpThread;
std::wstring g_dumpPath;
ur::ScanComparison g_comparison;
std::vector<ur::Group> g_newResults;
std::vector<ur::Group> g_previousComplete;
ur::SessionDelta g_liveDelta;
std::string g_scanContext;
bool g_hasComparison = false;
HFONT g_font = nullptr, g_fontHdr = nullptr, g_fontMono = nullptr;
int g_dpi = 96;
RECT g_segRect{};
RECT g_fields[5]{};
struct Load {
    RECT rect{};
    HWND tip = nullptr;
    double cpu = -1, gpu = -1, own = 0;
    ULONGLONG idle = 0, total = 0, mine = 0, at = 0;
    std::atomic<double> gpuNow{-1};
    HANDLE stop = nullptr;
    std::thread worker;
} g_load;
RECT g_listCard{};
int S(int v) { return MulDiv(v, g_dpi, 96); }
HBRUSH g_bgBrush = nullptr, g_bg2Brush = nullptr;

std::vector<fxchain::RipProcess> g_procsAll;   // full enumeration
std::vector<fxchain::RipProcess> g_procsView;  // what the combo currently shows
std::atomic<bool> g_cancelFlag{false};
std::atomic<bool> g_closing{false};      /* window going away: stops a running dump */
ur::ScanGate g_scanGate;
std::atomic<bool> g_scanning{false};
std::atomic<long long> g_elapsedMs{0};
std::vector<ur::Group> g_lastResults;
std::vector<ur::Group> g_viewResults;   /* folded, what the list shows */
std::vector<ur::Group> g_viewHits;      /* the same rows unfolded: exports, dashboard, sessions */
struct ResultRow { int group, item; };       // item -1: the group's header row
std::vector<ResultRow> g_rows;                  /* the virtual list: per group a header, then its values */
std::vector<ur::Group> g_base;                  /* folded and ignore-filtered, what the text filter runs over */
std::size_t g_baseHidden = 0, g_baseRows = 0;
const COLORREF kSel = RGB(0x34, 0x36, 0x44);    /* selected rows: grey, not system white */
std::wstring g_statusFull;
ur::Mode g_lastMode = ur::Mode::Urls;
std::vector<std::filesystem::path> g_chosenPaths;
std::vector<std::filesystem::path> g_autoRipPaths;
uint32_t g_autoRipPid = 0;
bool g_elevated = false;
bool g_scanDeniedFiles = false;
uint32_t g_scanPid = 0;
bool g_scanDenied = false;
bool g_scanNeedsElev = false;
uint32_t g_resultsPid = 0;                     /* pid whose results are shown, for cleanup */
std::vector<uint32_t> g_scanPids, g_resultsPids;  /* same, when all instances of a name were scanned */
ur::ScanProgress g_progress;
ur::FileSelection g_fileSelection;
std::string g_scanError;
std::thread g_scanThread;

/* auto-update state, all touched only on the UI thread except the worker
   below, which only PostMessages back. See update.hpp. */
std::filesystem::path appDataDir();
void fillPresetPick();
bool g_portable = false;                           // data next to the exe
ur::UpdatePrefs g_updatePrefs;
ur::UpdateInfo g_update;
std::thread g_updateThread;
std::atomic<bool> g_updateBusy{false};
bool g_updateManual = false;                       // true while a user-triggered check runs
HANDLE g_instanceMutex = nullptr;                  // single-instance guard, released before an update relaunch
ur::IgnoreRules g_ignore;                          // rules in effect
std::vector<std::string> g_ignoreLines;            // as the user wrote them, kept in the workspace db
std::atomic<std::size_t> g_scanTargetsDenied{0};
std::filesystem::path dataFile(const wchar_t* name);
std::filesystem::path updatePrefsPath() { return dataFile(L"update.ini"); }
std::vector<ur::UserPreset> g_userPresets;
std::filesystem::path g_presetPath;
std::string g_activePreset;
std::vector<std::pair<std::string, std::string>> g_profileExtras;
std::vector<std::string> g_profileNames;
bool g_applyingPreset = false;

void applyFonts();
void startUpdateCheck(bool manual);
void fitColumns();
void layout(int cw, int ch);
void relayout(HWND hwnd);
void setSourcePaths(std::vector<std::filesystem::path> paths);
void clearResults();
void enableResultActions(bool on);
void setRegexMode();

bool isChecked(HWND h);
void setChecked(HWND h, bool on);

HWND mkStatic(HWND p, const wchar_t* t, DWORD extra = 0) {
    return CreateWindowExW(0, L"STATIC", t, WS_CHILD | WS_VISIBLE | SS_LEFT | extra,
                           0, 0, 0, 0, p, nullptr, nullptr, nullptr);
}
HWND mkButton(HWND p, const wchar_t* t, int id, DWORD style = 0) {
    return CreateWindowExW(0, L"BUTTON", t, WS_CHILD | WS_VISIBLE | WS_TABSTOP | style,
                           0, 0, 0, 0, p, (HMENU)(INT_PTR)id, nullptr, nullptr);
}
HWND mkPush(HWND p, const wchar_t* t, int id) { return mkButton(p, t, id, BS_OWNERDRAW); }
HWND mkChip(HWND p, const wchar_t* t, int id) { return mkButton(p, t, id, BS_OWNERDRAW); }
HWND mkSection(HWND p, const wchar_t* t) {
    return CreateWindowExW(0, L"STATIC", t, WS_CHILD | WS_VISIBLE | SS_OWNERDRAW,
                           0, 0, 0, 0, p, nullptr, nullptr, nullptr);
}

void roundRect(HDC dc, RECT r, int rad, COLORREF fill, COLORREF border) {
    HBRUSH b = CreateSolidBrush(fill);
    HPEN pen = CreatePen(PS_SOLID, 1, border);
    HGDIOBJ ob = SelectObject(dc, b), op = SelectObject(dc, pen);
    RoundRect(dc, r.left, r.top, r.right, r.bottom, rad, rad);
    SelectObject(dc, ob); SelectObject(dc, op);
    DeleteObject(b); DeleteObject(pen);
}

void inkText(HDC dc, const wchar_t* t, RECT r, HFONT f, COLORREF c, UINT fmt, int track = 0) {
    HFONT of = (HFONT)SelectObject(dc, f);
    int oe = SetTextCharacterExtra(dc, track);
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, c);
    DrawTextW(dc, t, -1, &r, fmt);
    SetTextCharacterExtra(dc, oe);
    SelectObject(dc, of);
}

void darkTitle(HWND h) {
    BOOL dark = TRUE;
    DwmSetWindowAttribute(h, 20 /*DWMWA_USE_IMMERSIVE_DARK_MODE*/, &dark, sizeof(dark));
}

/* a combo's open list hangs under its rounded field (g_fields[ref]), as wide, with round corners on Win11 */
LRESULT CALLBACK dropSub(HWND h, UINT msg, WPARAM wp, LPARAM lp, UINT_PTR, DWORD_PTR ref) {
    if (msg == WM_WINDOWPOSCHANGING) {
        auto* wpos = (WINDOWPOS*)lp;
        if (!(wpos->flags & SWP_NOMOVE) || !(wpos->flags & SWP_NOSIZE)) {
            RECT f = g_fields[ref], cur; MapWindowPoints(g_main, nullptr, (POINT*)&f, 2);
            GetWindowRect(h, &cur);
            const int cx = std::max<int>(f.right - f.left, (wpos->flags & SWP_NOSIZE) ? cur.right - cur.left : wpos->cx);
            const int cy = (wpos->flags & SWP_NOSIZE) ? cur.bottom - cur.top : wpos->cy;
            const int y = (wpos->flags & SWP_NOMOVE) ? cur.top : wpos->y;
            const int gap = MulDiv(3, (int)GetDpiForWindow(g_main), 96);
            wpos->x = f.left; wpos->cx = cx; wpos->cy = cy;
            wpos->y = y < f.top ? f.top - cy - gap : f.bottom + gap;
            MONITORINFO mi{sizeof(mi)};
            if (GetMonitorInfoW(MonitorFromRect(&f, MONITOR_DEFAULTTONEAREST), &mi)) {
                wpos->x = std::max<int>(mi.rcWork.left, std::min<int>(wpos->x, mi.rcWork.right - cx));
                wpos->y = std::max<int>(mi.rcWork.top, std::min<int>(wpos->y, mi.rcWork.bottom - cy));
            }
            wpos->flags &= ~(SWP_NOMOVE | SWP_NOSIZE);
        }
    }
    if (msg == WM_NCDESTROY) RemoveWindowSubclass(h, dropSub, ref);
    return DefSubclassProc(h, msg, wp, lp);
}
void roundDrop(HWND combo, int field) {
    COMBOBOXINFO ci{sizeof(ci)};
    if (!GetComboBoxInfo(combo, &ci) || !ci.hwndList) return;
    int round = 2;      /* DWMWCP_ROUND; Win10 ignores it */
    DwmSetWindowAttribute(ci.hwndList, 33 /*DWMWA_WINDOW_CORNER_PREFERENCE*/, &round, sizeof(round));
    SetWindowSubclass(ci.hwndList, dropSub, field, field);
}

bool isMode(HWND h) { return h == g_modeUrl || h == g_modeRegex; }
bool isChip(HWND h) {
    for (HWND t : {g_ascii, g_utf16, g_b64, g_hex, g_esc, g_pEmail, g_pIpv4, g_pIpv6, g_pGuid, g_pApi, g_pPath,
                   g_pDl, g_crap, g_newOnly, g_allInst, g_ignoreChip})
        if (t == h) return true;
    return false;
}

void drawPush(const DRAWITEMSTRUCT* d) {
    const bool dis = (d->itemState & ODS_DISABLED) != 0;
    const bool down = (d->itemState & ODS_SELECTED) != 0;
    const bool hot = (SendMessageW(d->hwndItem, BM_GETSTATE, 0, 0) & BST_HOT) != 0;
    const bool prim = d->hwndItem == g_scan;
    COLORREF fill, bord, ink;
    if (prim) {
        fill = dis ? kBg3 : (down ? kAccent : (hot ? kAccentHot : kAccent));
        bord = dis ? kBDef : fill;
        ink = dis ? kText3 : RGB(0xFF, 0xFF, 0xFF);
    } else {
        fill = dis ? kBg : (down || hot ? kBg3 : kBg2);
        bord = (d->itemState & ODS_FOCUS) ? kBFoc : kBDef;
        ink = dis ? kText3 : kText;
    }
    FillRect(d->hDC, &d->rcItem, g_bgBrush);
    roundRect(d->hDC, d->rcItem, S(20), fill, bord);
    wchar_t t[64] = L"";
    GetWindowTextW(d->hwndItem, t, 64);
    inkText(d->hDC, t, d->rcItem, g_font, ink, DT_SINGLELINE | DT_CENTER | DT_VCENTER);
}

void drawChip(const DRAWITEMSTRUCT* d) {
    const bool on = isChecked(d->hwndItem);
    const bool hot = (SendMessageW(d->hwndItem, BM_GETSTATE, 0, 0) & BST_HOT) != 0;
    FillRect(d->hDC, &d->rcItem, g_bgBrush);
    roundRect(d->hDC, d->rcItem, d->rcItem.bottom - d->rcItem.top,
              on ? kAccentMuted : kBg, on ? kAccent : (hot ? kBFoc : kBDef));
    wchar_t t[64] = L"";
    GetWindowTextW(d->hwndItem, t, 64);
    inkText(d->hDC, t, d->rcItem, g_font, on ? kAccent2 : kText2, DT_SINGLELINE | DT_CENTER | DT_VCENTER);
}

void drawMode(const DRAWITEMSTRUCT* d) {
    const bool on = isChecked(d->hwndItem);
    HBRUSH b = CreateSolidBrush(kBg);
    FillRect(d->hDC, &d->rcItem, b);
    DeleteObject(b);
    wchar_t t[64] = L"";
    GetWindowTextW(d->hwndItem, t, 64);
    if (on) roundRect(d->hDC, d->rcItem, S(16), kAccent, kAccent);
    inkText(d->hDC, t, d->rcItem, g_font, on ? RGB(0xFF, 0xFF, 0xFF) : kText2,
            DT_SINGLELINE | DT_CENTER | DT_VCENTER);
}

void drawSection(const DRAWITEMSTRUCT* d) {
    FillRect(d->hDC, &d->rcItem, g_bgBrush);
    wchar_t t[64] = L"";
    GetWindowTextW(d->hwndItem, t, 64);
    inkText(d->hDC, t, d->rcItem, g_fontHdr, kText2, DT_SINGLELINE | DT_VCENTER, S(2));
}

void drawCombo(const DRAWITEMSTRUCT* d) {
    HBRUSH b = CreateSolidBrush((d->itemState & ODS_SELECTED) ? kAccentMuted : kBg2);
    FillRect(d->hDC, &d->rcItem, b);
    DeleteObject(b);
    if ((int)d->itemID < 0) return;
    const LRESULT len = SendMessageW(d->hwndItem, CB_GETLBTEXTLEN, d->itemID, 0);
    if (len < 0) return;
    std::wstring text(size_t(len) + 1, L'\0');
    SendMessageW(d->hwndItem, CB_GETLBTEXT, d->itemID, (LPARAM)text.data());
    const wchar_t* t = text.c_str();
    HFONT of = (HFONT)SelectObject(d->hDC, g_font);
    SetBkMode(d->hDC, TRANSPARENT);
    SetTextColor(d->hDC, kText);
    RECT r = d->rcItem; r.left += S(6);
    DrawTextW(d->hDC, t, -1, &r, DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);
    SelectObject(d->hDC, of);
}

void drawCheck(const NMCUSTOMDRAW* d) {
    const LRESULT st = SendMessageW(d->hdr.hwndFrom, BM_GETSTATE, 0, 0);
    const bool on = (st & BST_CHECKED) != 0, hot = (st & (BST_HOT | BST_PUSHED)) != 0;
    const int n = S(14), y = (d->rc.top + d->rc.bottom - n) / 2;
    RECT r = d->rc, k{r.left, y, r.left + n, y + n};
    FillRect(d->hdc, &r, g_bgBrush);
    const COLORREF fill = on ? (hot ? kAccentHot : kAccent) : kBg2;
    roundRect(d->hdc, k, S(6), fill, (st & BST_FOCUS) ? kAccent2 : on ? fill : hot ? kText2 : kText3);
    if (on) {
        HPEN pen = CreatePen(PS_SOLID, S(2), RGB(0xFF, 0xFF, 0xFF));
        HGDIOBJ op = SelectObject(d->hdc, pen);
        POINT v[3] = {{k.left + S(3), y + S(7)}, {k.left + S(6), y + S(10)}, {k.left + S(11), y + S(4)}};
        Polyline(d->hdc, v, 3);
        SelectObject(d->hdc, op); DeleteObject(pen);
    }
    wchar_t t[32] = L"";
    GetWindowTextW(d->hdr.hwndFrom, t, 32);
    r.left = k.right + S(6);
    inkText(d->hdc, t, r, g_font, kText, DT_SINGLELINE | DT_VCENTER);
}

void setFont(HWND h, HFONT f) { SendMessageW(h, WM_SETFONT, (WPARAM)f, TRUE); }

int textW(HWND h, HFONT f, int track = 0) {
    wchar_t t[128] = L"";
    GetWindowTextW(h, t, 128);
    HDC dc = GetDC(h);
    HFONT of = (HFONT)SelectObject(dc, f);
    SIZE sz{};
    GetTextExtentPoint32W(dc, t, (int)wcslen(t), &sz);
    SelectObject(dc, of);
    ReleaseDC(h, dc);
    return sz.cx + track * (int)wcslen(t);
}

void makeFonts() {
    if (g_font) DeleteObject(g_font);
    if (g_fontHdr) DeleteObject(g_fontHdr);
    if (g_fontMono) DeleteObject(g_fontMono);
    g_fontMono = CreateFontW(-S(14), 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
                             OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                             FIXED_PITCH | FF_MODERN, L"Consolas");
    g_font = CreateFontW(-S(15), 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
                         OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                         DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    g_fontHdr = CreateFontW(-S(12), 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET,
                            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                            DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
}
struct Toggle { HWND h; bool on; };
std::vector<Toggle> g_toggles;

bool isChecked(HWND h) {
    for (const Toggle& t : g_toggles) if (t.h == h) return t.on;
    return false;
}
void setChecked(HWND h, bool on) {
    for (Toggle& t : g_toggles) if (t.h == h) { t.on = on; InvalidateRect(h, nullptr, TRUE); return; }
    g_toggles.push_back({h, on});
    InvalidateRect(h, nullptr, TRUE);
}

std::wstring controlText(HWND h) {
    int n = GetWindowTextLengthW(h);
    std::wstring s(static_cast<std::size_t>(n + 1), L'\0');
    if (n) GetWindowTextW(h, s.data(), n + 1);
    s.resize(static_cast<std::size_t>(n));
    return s;
}

std::filesystem::path presetFilePath() { return appDataDir() / L"regex-user-presets.ini"; }

void applyUserPreset(const ur::UserPreset& p) {
    g_applyingPreset = true;
    g_profileExtras.clear(); g_profileNames = {p.name};
    setChecked(g_ascii, p.ascii); setChecked(g_utf16, p.utf16);
    setChecked(g_hex, p.hex); setChecked(g_b64, p.base64); setChecked(g_esc, p.escaped);
    setChecked(g_pEmail, p.email); setChecked(g_pIpv4, p.ipv4);
    setChecked(g_pIpv6, p.ipv6); setChecked(g_pGuid, p.guid);
    setChecked(g_pApi, p.apiKey); setChecked(g_pPath, p.filepath); setChecked(g_pDl, p.download);
    SetWindowTextW(g_custom, p.custom ? widen(p.pattern).c_str() : L"");
    g_activePreset = p.name;
    setRegexMode();
    g_applyingPreset = false;
    SetWindowTextW(g_status, (L"Preset loaded: " + widen(p.name)).c_str());
}

enum : int {
    PE_LIST = 5000, PE_NAME, PE_DESC, PE_REGEX, PE_NEW, PE_DELETE, PE_VALIDATE, PE_SAVE, PE_USE, PE_CLOSE,
    PE_ASCII, PE_UTF16, PE_HEX, PE_BASE64, PE_ESCAPED, PE_CUSTOM, PE_EMAIL, PE_IPV4, PE_IPV6,
    PE_GUID, PE_APIKEY, PE_FILEPATH, PE_DOWNLOAD, PE_SAMPLE, PE_TEST, PE_ADD_PROFILE,
    PE_POSITIVE, PE_NEGATIVE, PE_RUN_CASES, PE_T_PRESETS, PE_T_NAME, PE_T_DESC, PE_T_REGEX,
    PE_T_DECODERS, PE_T_MODES, PE_STATUS, PE_T_SAMPLE, PE_T_POSITIVE, PE_T_NEGATIVE, PE_UP, PE_DOWN, PE_SORT
};

HWND g_pe = nullptr, g_peList, g_peName, g_peDesc, g_peRegex, g_peStatus;
HWND g_peAscii, g_peUtf16, g_peHex, g_peBase64, g_peEscaped, g_peCustom, g_peEmail, g_peIpv4, g_peIpv6;
HWND g_peGuid, g_peApi, g_pePath, g_peDownload;
HWND g_peSample, g_pePositive, g_peNegative;
int g_peIndex = -1;
bool g_peLoading = false;
std::string g_peSaved;

bool peCheck(HWND h) { return SendMessageW(h, BM_GETCHECK, 0, 0) == BST_CHECKED; }
void peCheck(HWND h, bool on) { SendMessageW(h, BM_SETCHECK, on ? BST_CHECKED : BST_UNCHECKED, 0); }

HWND peCtl(HWND p, const wchar_t* cls, const wchar_t* text, int id, DWORD style,
           int x = 0, int y = 0, int w = 0, int h = 0) {
    HWND c = CreateWindowExW(0, cls, text, WS_CHILD | WS_VISIBLE | WS_TABSTOP | style,
                             S(x), S(y), S(w), S(h), p, (HMENU)(INT_PTR)id, nullptr, nullptr);
    SendMessageW(c, WM_SETFONT, (WPARAM)g_font, TRUE);
    SetWindowTheme(c, L"DarkMode_Explorer", nullptr);
    return c;
}

void peFillList() {
    SendMessageW(g_peList, LB_RESETCONTENT, 0, 0);
    for (std::size_t i = 0; i < g_userPresets.size(); ++i)
        SendMessageW(g_peList, LB_ADDSTRING, 0, (LPARAM)(std::to_wstring(i + 1) + L". " + widen(g_userPresets[i].name)).c_str());
}

void peRead() {
    if (g_peIndex < 0 || g_peIndex >= (int)g_userPresets.size()) return;
    auto& p = g_userPresets[g_peIndex];
    p.name = ur::presetTrim(narrow(controlText(g_peName).c_str()));
    p.description = narrow(controlText(g_peDesc).c_str());
    p.pattern = narrow(controlText(g_peRegex).c_str());
    p.positiveExamples = narrow(controlText(g_pePositive).c_str());
    p.negativeExamples = narrow(controlText(g_peNegative).c_str());
    p.ascii = peCheck(g_peAscii); p.utf16 = peCheck(g_peUtf16);
    p.hex = peCheck(g_peHex); p.base64 = peCheck(g_peBase64); p.escaped = peCheck(g_peEscaped);
    p.custom = peCheck(g_peCustom); p.email = peCheck(g_peEmail);
    p.ipv4 = peCheck(g_peIpv4); p.ipv6 = peCheck(g_peIpv6);
    p.guid = peCheck(g_peGuid); p.apiKey = peCheck(g_peApi);
    p.filepath = peCheck(g_pePath); p.download = peCheck(g_peDownload);
}

void peShow(int i) {
    if (i < 0 || i >= (int)g_userPresets.size()) return;
    g_peIndex = i;
    g_peLoading = true;
    const auto& p = g_userPresets[i];
    SetWindowTextW(g_peName, widen(p.name).c_str());
    SetWindowTextW(g_peDesc, widen(p.description).c_str());
    SetWindowTextW(g_peRegex, widen(p.pattern).c_str());
    SetWindowTextW(g_pePositive, widen(p.positiveExamples).c_str());
    SetWindowTextW(g_peNegative, widen(p.negativeExamples).c_str());
    peCheck(g_peAscii, p.ascii); peCheck(g_peUtf16, p.utf16);
    peCheck(g_peHex, p.hex); peCheck(g_peBase64, p.base64); peCheck(g_peEscaped, p.escaped);
    peCheck(g_peCustom, p.custom); peCheck(g_peEmail, p.email);
    peCheck(g_peIpv4, p.ipv4); peCheck(g_peIpv6, p.ipv6);
    peCheck(g_peGuid, p.guid); peCheck(g_peApi, p.apiKey);
    peCheck(g_pePath, p.filepath); peCheck(g_peDownload, p.download);
    g_peLoading = false;
    SendMessageW(g_peList, LB_SETCURSEL, i, 0);
    SetWindowTextW(g_peStatus, p.validated ? L"Regex status: validated" : L"Regex status: not validated");
}

bool peValidate(bool announce) {
    peRead();
    if (g_peIndex < 0) return false;
    auto& p = g_userPresets[g_peIndex];
    try {
        ur::Detector d(ur::presetOptions(p)); p.validated = true;
    }
    catch (const ur::RegexError& e) {
        p.validated = false;
        SetWindowTextW(g_peStatus, widen(std::string("Regex error: ") + e.what()).c_str());
        if (announce) MessageBoxW(g_pe, widen(e.what()).c_str(), L"Regex syntax error", MB_OK | MB_ICONERROR);
        return false;
    }
    SetWindowTextW(g_peStatus, L"Regex status: validated");
    if (announce) MessageBoxW(g_pe, L"The regex and selected modes are valid.", L"Regex syntax", MB_OK | MB_ICONINFORMATION);
    return true;
}

bool peNamesValid() {
    for (std::size_t i = 0; i < g_userPresets.size(); ++i) {
        const auto& n = g_userPresets[i].name;
        if (ur::presetTrim(n).empty() || n.find_first_of("]\r\n") != std::string::npos) return false;
        for (std::size_t j = i + 1; j < g_userPresets.size(); ++j)
            if (_stricmp(n.c_str(), g_userPresets[j].name.c_str()) == 0) return false;
    }
    return true;
}

bool peSave(HWND h) {
    peRead();
    if (!peNamesValid()) {
        SetWindowTextW(g_peStatus, L"Use unique, non-empty names without ']'.");
        return false;
    }
    std::string e;
    if (!ur::saveUserPresets(g_presetPath, g_userPresets, &e)) {
        SetWindowTextW(g_peStatus, widen(e).c_str());
        return false;
    }
    g_peSaved = ur::serializeUserPresets(g_userPresets);
    SetWindowTextW(g_peStatus, L"Saved. Previous valid settings kept in .bak.");
    peFillList(); SendMessageW(g_peList, LB_SETCURSEL, g_peIndex, 0);
    return true;
}

void peClose(HWND h, bool use = false) {
    peRead();
    ur::UserPreset selected;
    if (use) selected = g_userPresets[g_peIndex];
    if (ur::serializeUserPresets(g_userPresets) != g_peSaved) {
        int choice = MessageBoxW(h, L"Save preset changes before closing?", L"Regex User Presets",
                                MB_YESNOCANCEL | MB_ICONQUESTION);
        if (choice == IDCANCEL || (choice == IDYES && !peSave(h))) return;
        if (choice == IDNO) g_userPresets = ur::parseUserPresets(g_peSaved);
    }
    if (use) applyUserPreset(selected);
    DestroyWindow(h);
}

void peLayout(HWND h, int cw, int ch) {
    cw = MulDiv(cw, 96, g_dpi); ch = MulDiv(ch, 96, g_dpi);
    const int w = cw - 250, f = std::max(ch - 468, 80);
    const int fd = f * 62 / 270, fr = f * 70 / 270, fs = f * 68 / 270, fe = f - fd - fr - fs;
    const int a = fd + fr, b = a + fs, pw = (w - 13) * 222 / 457, nx = 233 + pw, nw = w - 13 - pw;
    const int L[][5] = {
        {PE_T_PRESETS, 14, 12, 190, 20}, {PE_LIST, 14, 34, 190, 298 + a},
        {PE_NEW, 14, 344 + a, 88, 28}, {PE_DELETE, 112, 344 + a, 92, 28},
        {PE_UP, 14, 377 + a, 56, 26}, {PE_DOWN, 76, 377 + a, 60, 26}, {PE_SORT, 142, 377 + a, 62, 26},
        {PE_TEST, 14, 408 + a, 190, 28}, {PE_ADD_PROFILE, 14, 443 + a, 190, 28}, {PE_RUN_CASES, 14, 444 + b, 190, 28},
        {PE_T_NAME, 220, 12, w, 20}, {PE_NAME, 220, 34, w, 26},
        {PE_T_DESC, 220, 70, w, 20}, {PE_DESC, 220, 92, w, fd},
        {PE_T_REGEX, 220, 102 + fd, w, 20}, {PE_REGEX, 220, 124 + fd, w, fr},
        {PE_T_DECODERS, 220, 136 + a, w, 20}, {PE_ASCII, 220, 158 + a, 90, 24}, {PE_UTF16, 315, 158 + a, 90, 24},
        {PE_HEX, 410, 158 + a, 90, 24}, {PE_BASE64, 505, 158 + a, 100, 24}, {PE_ESCAPED, 600, 158 + a, 90, 24},
        {PE_T_MODES, 220, 192 + a, w, 20}, {PE_CUSTOM, 220, 214 + a, 90, 24}, {PE_EMAIL, 315, 214 + a, 90, 24},
        {PE_IPV4, 410, 214 + a, 90, 24}, {PE_IPV6, 505, 214 + a, 90, 24}, {PE_GUID, 600, 214 + a, 90, 24},
        {PE_APIKEY, 220, 242 + a, 90, 24}, {PE_FILEPATH, 315, 242 + a, 90, 24}, {PE_DOWNLOAD, 410, 242 + a, 100, 24},
        {PE_STATUS, 220, 278 + a, w, 22},
        {PE_VALIDATE, 220, 344 + a, 112, 28}, {PE_SAVE, 342, 344 + a, 100, 28},
        {PE_USE, 452, 344 + a, 112, 28}, {PE_CLOSE, 574, 344 + a, 116, 28},
        {PE_T_SAMPLE, 220, 384 + a, w, 20}, {PE_SAMPLE, 220, 408 + a, w, fs},
        {PE_T_POSITIVE, 220, 420 + b, pw, 20}, {PE_T_NEGATIVE, nx, 420 + b, nw, 20},
        {PE_POSITIVE, 220, 444 + b, pw, fe}, {PE_NEGATIVE, nx, 444 + b, nw, fe},
    };
    for (const auto& l : L) MoveWindow(GetDlgItem(h, l[0]), S(l[1]), S(l[2]), S(l[3]), S(l[4]), TRUE);
}

LRESULT CALLBACK PresetProc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        darkTitle(h);
        g_peIndex = -1;
        g_peSaved = ur::serializeUserPresets(g_userPresets);
        peCtl(h, L"STATIC", L"Presets", PE_T_PRESETS, 0);
        g_peList = peCtl(h, L"LISTBOX", L"", PE_LIST, LBS_NOTIFY | LBS_NOINTEGRALHEIGHT | WS_BORDER | WS_VSCROLL);
        peCtl(h, L"STATIC", L"Name", PE_T_NAME, 0);
        g_peName = peCtl(h, L"EDIT", L"", PE_NAME, ES_AUTOHSCROLL | WS_BORDER);
        peCtl(h, L"STATIC", L"Description", PE_T_DESC, 0);
        g_peDesc = peCtl(h, L"EDIT", L"", PE_DESC, ES_MULTILINE | ES_AUTOVSCROLL | WS_BORDER | WS_VSCROLL);
        peCtl(h, L"STATIC", L"Regex (ECMAScript)", PE_T_REGEX, 0);
        g_peRegex = peCtl(h, L"EDIT", L"", PE_REGEX, ES_MULTILINE | ES_AUTOVSCROLL | WS_BORDER | WS_VSCROLL);
        peCtl(h, L"STATIC", L"Decoders", PE_T_DECODERS, 0);
        g_peAscii = peCtl(h, L"BUTTON", L"ASCII", PE_ASCII, BS_AUTOCHECKBOX);
        g_peUtf16 = peCtl(h, L"BUTTON", L"UTF-16", PE_UTF16, BS_AUTOCHECKBOX);
        g_peHex = peCtl(h, L"BUTTON", L"Hex", PE_HEX, BS_AUTOCHECKBOX);
        g_peBase64 = peCtl(h, L"BUTTON", L"Base64", PE_BASE64, BS_AUTOCHECKBOX);
        g_peEscaped = peCtl(h, L"BUTTON", L"Escaped", PE_ESCAPED, BS_AUTOCHECKBOX);
        peCtl(h, L"STATIC", L"Regex modes", PE_T_MODES, 0);
        g_peCustom = peCtl(h, L"BUTTON", L"Custom", PE_CUSTOM, BS_AUTOCHECKBOX);
        g_peEmail = peCtl(h, L"BUTTON", L"Email", PE_EMAIL, BS_AUTOCHECKBOX);
        g_peIpv4 = peCtl(h, L"BUTTON", L"IPv4", PE_IPV4, BS_AUTOCHECKBOX);
        g_peIpv6 = peCtl(h, L"BUTTON", L"IPv6", PE_IPV6, BS_AUTOCHECKBOX);
        g_peGuid = peCtl(h, L"BUTTON", L"GUID", PE_GUID, BS_AUTOCHECKBOX);
        g_peApi = peCtl(h, L"BUTTON", L"API key", PE_APIKEY, BS_AUTOCHECKBOX);
        g_pePath = peCtl(h, L"BUTTON", L"File path", PE_FILEPATH, BS_AUTOCHECKBOX);
        g_peDownload = peCtl(h, L"BUTTON", L"Download", PE_DOWNLOAD, BS_AUTOCHECKBOX);
        g_peStatus = peCtl(h, L"STATIC", L"Regex status: not validated", PE_STATUS, 0);
        peCtl(h, L"STATIC", L"Test text: one candidate per line (patterns only)", PE_T_SAMPLE, 0);
        g_peSample = peCtl(h, L"EDIT", L"", PE_SAMPLE,
            ES_MULTILINE | ES_AUTOVSCROLL | ES_WANTRETURN | WS_BORDER | WS_VSCROLL);
        SendMessageW(g_peSample, EM_SETLIMITTEXT, 2048, 0);
        peCtl(h, L"BUTTON", L"Test sample", PE_TEST, BS_PUSHBUTTON);
        peCtl(h, L"BUTTON", L"Add to profile", PE_ADD_PROFILE, BS_PUSHBUTTON);
        peCtl(h, L"STATIC", L"Positive examples (one per line)", PE_T_POSITIVE, 0);
        peCtl(h, L"STATIC", L"Negative examples (one per line)", PE_T_NEGATIVE, 0);
        g_pePositive = peCtl(h, L"EDIT", L"", PE_POSITIVE,
            ES_MULTILINE | ES_AUTOVSCROLL | ES_WANTRETURN | WS_BORDER | WS_VSCROLL);
        g_peNegative = peCtl(h, L"EDIT", L"", PE_NEGATIVE,
            ES_MULTILINE | ES_AUTOVSCROLL | ES_WANTRETURN | WS_BORDER | WS_VSCROLL);
        peCtl(h, L"BUTTON", L"Run saved cases", PE_RUN_CASES, BS_PUSHBUTTON);
        peCtl(h, L"BUTTON", L"New", PE_NEW, BS_PUSHBUTTON);
        peCtl(h, L"BUTTON", L"Delete", PE_DELETE, BS_PUSHBUTTON);
        peCtl(h, L"BUTTON", L"Up", PE_UP, BS_PUSHBUTTON);
        peCtl(h, L"BUTTON", L"Down", PE_DOWN, BS_PUSHBUTTON);
        peCtl(h, L"BUTTON", L"Sort A-Z", PE_SORT, BS_PUSHBUTTON);
        peCtl(h, L"BUTTON", L"Check syntax", PE_VALIDATE, BS_PUSHBUTTON);
        peCtl(h, L"BUTTON", L"Save all", PE_SAVE, BS_PUSHBUTTON);
        peCtl(h, L"BUTTON", L"Use preset", PE_USE, BS_DEFPUSHBUTTON);
        peCtl(h, L"BUTTON", L"Close", PE_CLOSE, BS_PUSHBUTTON);
        peFillList();
        if (!g_userPresets.empty()) peShow(0);
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == PE_LIST && HIWORD(wp) == LBN_SELCHANGE) {
            int selected = (int)SendMessageW(g_peList, LB_GETCURSEL, 0, 0);
            peRead(); peFillList(); peShow(selected); return 0;
        }
        if (LOWORD(wp) == PE_NEW) {
            peRead(); ur::UserPreset p; p.name = "New preset"; g_userPresets.push_back(p);
            peFillList(); peShow((int)g_userPresets.size() - 1); SetFocus(g_peName); return 0;
        }
        if (LOWORD(wp) == PE_DELETE && g_peIndex >= 0) {
            int next = g_peIndex;
            g_userPresets.erase(g_userPresets.begin() + g_peIndex); peFillList();
            g_peIndex = -1;
            if (!g_userPresets.empty()) peShow(std::min<int>(next, (int)g_userPresets.size() - 1));
            else {
                SetWindowTextW(g_peName, L""); SetWindowTextW(g_peDesc, L""); SetWindowTextW(g_peRegex, L"");
                SetWindowTextW(g_peStatus, L"No preset selected. Click New to create one.");
            }
            return 0;
        }
        if ((LOWORD(wp) == PE_UP || LOWORD(wp) == PE_DOWN) && g_peIndex >= 0) {
            const int to = g_peIndex + (LOWORD(wp) == PE_UP ? -1 : 1);
            if (to < 0 || to >= (int)g_userPresets.size()) return 0;
            peRead(); std::swap(g_userPresets[g_peIndex], g_userPresets[to]);
            peFillList(); peShow(to); return 0;
        }
        if (LOWORD(wp) == PE_SORT && !g_userPresets.empty()) {
            peRead();
            const std::string cur = g_peIndex >= 0 ? g_userPresets[g_peIndex].name : std::string{};
            std::stable_sort(g_userPresets.begin(), g_userPresets.end(),
                [](const ur::UserPreset& x, const ur::UserPreset& y) { return _stricmp(x.name.c_str(), y.name.c_str()) < 0; });
            int at = 0;
            for (int i = 0; i < (int)g_userPresets.size(); ++i) if (g_userPresets[i].name == cur) at = i;
            peFillList(); peShow(at); return 0;
        }
        if (LOWORD(wp) == PE_VALIDATE) { peValidate(true); return 0; }
        if (LOWORD(wp) == PE_TEST) {
            if (!peValidate(false)) return 0;
            try {
                ur::Detector detector(ur::presetOptions(g_userPresets[g_peIndex]));
                ur::Sink sink;
                detector.testText(narrow(controlText(g_peSample).c_str()), sink);
                std::vector<ur::Sink> sinks; sinks.push_back(std::move(sink));
                auto groups = ur::mergeSinks(sinks);
                auto text = std::to_string(ur::countFindings(groups)) + " distinct matches\r\n\r\n" +
                    ur::exportResults(groups, "txt");
                if (text.size() > 8000) text = text.substr(0, 8000) + "\r\n(Display truncated)";
                MessageBoxW(h, widen(text).c_str(), L"Regex sample results", MB_OK | MB_ICONINFORMATION);
            } catch (const std::exception& e) { SetWindowTextW(g_peStatus, widen(e.what()).c_str()); }
            return 0;
        }
        if (LOWORD(wp) == PE_ADD_PROFILE && g_peIndex >= 0) {
            if (!peValidate(false)) return 0;
            const auto& p = g_userPresets[g_peIndex];
            if (std::find(g_profileNames.begin(), g_profileNames.end(), p.name) != g_profileNames.end()) {
                SetWindowTextW(g_peStatus, L"This preset is already in the active profile."); return 0;
            }
            if (g_profileNames.empty()) applyUserPreset(p);
            else {
                g_profileNames.push_back(p.name);
                if (p.custom && !p.pattern.empty()) g_profileExtras.emplace_back(p.name, p.pattern);
                for (auto [control, on] : {std::pair{g_ascii, p.ascii}, {g_utf16, p.utf16},
                     {g_hex, p.hex}, {g_b64, p.base64}, {g_esc, p.escaped}, {g_pEmail, p.email}, {g_pIpv4, p.ipv4},
                     {g_pIpv6, p.ipv6}, {g_pGuid, p.guid}, {g_pApi, p.apiKey},
                     {g_pPath, p.filepath}, {g_pDl, p.download}})
                    if (on) setChecked(control, true);
            }
            SetWindowTextW(g_peStatus, (L"Active profile: " + std::to_wstring(g_profileNames.size()) + L" presets").c_str());
            SetWindowTextW(g_presets, (L"Profile (" + std::to_wstring(g_profileNames.size()) + L")...").c_str());
            relayout(g_main);
            return 0;
        }
        if (LOWORD(wp) == PE_RUN_CASES && g_peIndex >= 0) {
            if (!peValidate(false)) return 0;
            try {
                auto report = ur::testPresetExamples(g_userPresets[g_peIndex]);
                auto summary = std::to_string(report.passed) + " passed, " +
                    std::to_string(report.failed) + " failed";
                for (const auto& failure : report.failures) summary += "\r\n" + failure;
                MessageBoxW(h, widen(summary).c_str(), L"Preset test cases",
                    MB_OK | (report.failed ? MB_ICONWARNING : MB_ICONINFORMATION));
            } catch (const std::exception& e) { SetWindowTextW(g_peStatus, widen(e.what()).c_str()); }
            return 0;
        }
        if (LOWORD(wp) == PE_SAVE) {
            peSave(h);
            return 0;
        }
        if (LOWORD(wp) == PE_USE && g_peIndex >= 0) {
            if (peValidate(false)) peClose(h, true);
            return 0;
        }
        if (LOWORD(wp) == PE_CLOSE || LOWORD(wp) == IDCANCEL) { peClose(h); return 0; }
        if (!g_peLoading && g_peIndex >= 0 &&
            ((LOWORD(wp) == PE_REGEX && HIWORD(wp) == EN_CHANGE) ||
             (LOWORD(wp) >= PE_ASCII && LOWORD(wp) <= PE_DOWNLOAD && HIWORD(wp) == BN_CLICKED))) {
            g_userPresets[g_peIndex].validated = false;
            SetWindowTextW(g_peStatus, L"Regex status: not validated");
        }
        break;
    case WM_SIZE:
        if (wp != SIZE_MINIMIZED) peLayout(h, LOWORD(lp), HIWORD(lp));
        return 0;
    case WM_GETMINMAXINFO: {
        RECT r{0, 0, S(720), S(612)};
        AdjustWindowRectEx(&r, (DWORD)GetWindowLongPtrW(h, GWL_STYLE), FALSE, (DWORD)GetWindowLongPtrW(h, GWL_EXSTYLE));
        ((MINMAXINFO*)lp)->ptMinTrackSize = {r.right - r.left, r.bottom - r.top};
        return 0;
    }
    case WM_NOTIFY: {
        auto d = (const NMCUSTOMDRAW*)lp;
        const int id = (int)d->hdr.idFrom;
        if (d->hdr.code != NM_CUSTOMDRAW || id < PE_ASCII || id > PE_DOWNLOAD) break;
        if (d->dwDrawStage != CDDS_PREPAINT) return CDRF_DODEFAULT;
        drawCheck(d); return CDRF_SKIPDEFAULT;
    }
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLORBTN: {
        HDC dc = (HDC)wp; SetTextColor(dc, kText); SetBkColor(dc, kBg); return (LRESULT)g_bgBrush;
    }
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORLISTBOX: {
        HDC dc = (HDC)wp; SetTextColor(dc, kText); SetBkColor(dc, kBg2); return (LRESULT)g_bg2Brush;
    }
    case WM_ERASEBKGND: {
        RECT r; GetClientRect(h, &r); FillRect((HDC)wp, &r, g_bgBrush); return 1;
    }
    case WM_CLOSE: peClose(h); return 0;
    case WM_DESTROY:
        g_pe = nullptr; EnableWindow(g_main, TRUE);
        fillPresetPick();
        if (IsIconic(g_main)) ShowWindow(g_main, SW_RESTORE);
        SetForegroundWindow(g_main); return 0;
    }
    return DefWindowProcW(h, msg, wp, lp);
}

void showPresetEditor() {
    if (g_pe) { SetForegroundWindow(g_pe); return; }
    WNDCLASSEXW wc{ sizeof(wc) };
    wc.lpfnWndProc = PresetProc; wc.hInstance = GetModuleHandleW(nullptr);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW); wc.hbrBackground = g_bgBrush;
    wc.hIcon = wc.hIconSm = LoadIconW(wc.hInstance, MAKEINTRESOURCEW(1));
    wc.lpszClassName = L"StringRipperPresetEditor";
    RegisterClassExW(&wc);
    const DWORD st = WS_CAPTION | WS_SYSMENU | WS_THICKFRAME | WS_MAXIMIZEBOX | WS_CLIPCHILDREN;
    RECT r{0, 0, S(720), S(738)}, m;
    AdjustWindowRectEx(&r, st, FALSE, WS_EX_DLGMODALFRAME);
    MONITORINFO mi{sizeof(mi)};
    GetMonitorInfoW(MonitorFromWindow(g_main, MONITOR_DEFAULTTONEAREST), &mi);
    GetWindowRect(g_main, &m);
    const RECT& a = mi.rcWork;
    const int w = std::min<int>(r.right - r.left, a.right - a.left), hh = std::min<int>(r.bottom - r.top, a.bottom - a.top);
    const int x = std::clamp<int>((m.left + m.right - w) / 2, a.left, a.right - w);
    const int y = std::clamp<int>((m.top + m.bottom - hh) / 2, a.top, a.bottom - hh);
    EnableWindow(g_main, FALSE);
    g_pe = CreateWindowExW(WS_EX_DLGMODALFRAME, wc.lpszClassName, L"Regex User Presets", st, x, y, w, hh,
                           nullptr, nullptr, wc.hInstance, nullptr);
    if (!g_pe) { EnableWindow(g_main, TRUE); return; }
    ShowWindow(g_pe, SW_SHOW); UpdateWindow(g_pe);
    ShowWindow(g_main, SW_SHOWMINNOACTIVE);
}

void showAbout() {
    std::string s;
    s += "StringRipper " STRINGRIPPER_VERSION "  by Akustikrausch\r\n";
    s += "build " UR_STR(STRINGRIPPER_BUILD) "  " __DATE__ "\r\n\r\n";
    s += "URLs and regex out of a process or files.\r\n";
    s += "Win32, C++20, static CRT, one exe, no DLLs.\r\n";
    s += "Scan on up to 16 workers. URL match hand-rolled, regex via std::regex.\r\n";
    s += "ASCII/ANSI/UTF-8, UTF-16, Base64, Hex.\r\n";
    s += "Reader from Akustikrausch's FXChainPlayer.\r\n";
    s += "Settings and workspace: " + narrow(appDataDir().wstring().c_str()) +
         (g_portable ? "  (next to the exe)\r\n\r\n" : "  (exe folder is read-only)\r\n\r\n");
    s += "Check for updates now?";
    if (MessageBoxW(g_main, widen(s).c_str(), L"About StringRipper",
                    MB_YESNO | MB_ICONINFORMATION) == IDYES)
        startUpdateCheck(true);
}

void fillCombo() {
    SendMessageW(g_source, CB_RESETCONTENT, 0, 0);
    for (const auto& p : g_procsView) {
        wchar_t line[256];
        _snwprintf_s(line, _TRUNCATE, L"%s   (pid %u, %llu MB%s%s)",
                     widen(p.name).c_str(), p.pid,
                     (unsigned long long)(p.workingSetBytes / (1024 * 1024)),
                     p.bits == 32 ? L", 32-bit" : L"",
                     p.access == fxchain::RipAccess::NeedsElevation ? L", needs admin" : L"");
        SendMessageW(g_source, CB_ADDSTRING, 0, (LPARAM)line);
    }
    if (!g_procsView.empty()) SendMessageW(g_source, CB_SETCURSEL, 0, 0);
}

void applyProcFilter() {
    wchar_t q[128] = L"";
    GetWindowTextW(g_search, q, 128);
    std::string query = lower(narrow(q));
    g_procsView.clear();
    for (const auto& p : g_procsAll) {
        if (query.empty() || lower(p.name).find(query) != std::string::npos) g_procsView.push_back(p);
    }
    fillCombo();
}

uint32_t selectedPid() {
    int sel = (int)SendMessageW(g_source, CB_GETCURSEL, 0, 0);
    return (sel >= 0 && sel < (int)g_procsView.size()) ? g_procsView[sel].pid : 0;
}
bool selectPid(uint32_t pid) {
    for (int i = 0; i < (int)g_procsView.size(); ++i)
        if (g_procsView[i].pid == pid) { SendMessageW(g_source, CB_SETCURSEL, i, 0); return true; }
    return false;
}

void sortProcs() {
    std::sort(g_procsAll.begin(), g_procsAll.end(),
              [](const fxchain::RipProcess& a, const fxchain::RipProcess& b) {
                  return _stricmp(a.name.c_str(), b.name.c_str()) < 0;
              });
}
void refreshProcesses() {
    g_procsAll = fxchain::ripBackend().enumerate();
    sortProcs();
    applyProcFilter();
}

/* poll: drop results whose process has exited. the full process list is costly (handles,
   audio sessions), so it is rebuilt only when pids changed and the list is about to be seen */
std::unordered_set<uint32_t> livePids() {
    std::vector<DWORD> ids(1024);
    DWORD got = 0;
    while (EnumProcesses(ids.data(), DWORD(ids.size() * sizeof(DWORD)), &got) && got == ids.size() * sizeof(DWORD))
        ids.resize(ids.size() * 2);
    return std::unordered_set<uint32_t>(ids.begin(), ids.begin() + got / sizeof(DWORD));
}
std::unordered_set<uint32_t> g_livePids;
struct ResultSlot {
    std::vector<ur::Group> last, fresh, previous;
    ur::ScanComparison comparison;
    ur::SessionDelta delta;
    std::string context;
    bool hasComparison = false;
    std::wstring status = L"Ready.", filter;
    uint32_t pid = 0;
    std::vector<uint32_t> pids;
} g_otherSlot;
bool g_procsStale = false;
/* rebuild the process list if pids changed since the last rebuild */
void syncProcs() {
    if (!g_procsStale) return;
    g_procsStale = false;
    auto now = fxchain::ripBackend().enumerate();
    std::unordered_set<uint32_t> before, listed;
    for (const auto& p : g_procsAll) before.insert(p.pid);
    for (const auto& p : now) listed.insert(p.pid);
    if (before == listed) return;
    uint32_t keep = selectedPid();
    g_procsAll = std::move(now);
    sortProcs();
    applyProcFilter();
    if (keep) selectPid(keep);
}
void autoRefreshProcs() {
    if (g_scanning) return;
    std::unordered_set<uint32_t> after = livePids();
    if (after.empty()) return;
    auto gone = [&](uint32_t p) { return !after.count(p); };
    if ((g_otherSlot.pid && gone(g_otherSlot.pid)) ||
        (!g_otherSlot.pids.empty() && std::all_of(g_otherSlot.pids.begin(), g_otherSlot.pids.end(), gone))) {
        std::wstring f = std::move(g_otherSlot.filter);
        g_otherSlot = ResultSlot{};
        g_otherSlot.filter = std::move(f);
        g_otherSlot.status = L"The scanned process exited; results cleared.";
    }
    if (after == g_livePids) return;
    g_livePids = after;
    if (!g_resultsPids.empty()) {
        g_resultsPids.erase(std::remove_if(g_resultsPids.begin(), g_resultsPids.end(),
                                           [&](uint32_t p) { return !after.count(p); }), g_resultsPids.end());
        if (g_resultsPids.empty()) {
            clearResults();
            g_statusFull = L"The scanned processes exited; results cleared.";
            SetWindowTextW(g_status, g_statusFull.c_str());
        }
    }
    if (g_resultsPid && !after.count(g_resultsPid)) {
        clearResults();
        g_statusFull = L"The scanned process exited; results cleared.";
        SetWindowTextW(g_status, g_statusFull.c_str());
    }
    g_procsStale = true;
    const uint32_t sel = selectedPid();     /* the rest waits for the dropdown or the search box */
    if (sel && !after.count(sel) && !SendMessageW(g_source, CB_GETDROPPEDSTATE, 0, 0)) syncProcs();
}

void pickFile() {
    wchar_t buf[4096] = L"";
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_main;
    ofn.lpstrFile = buf;
    ofn.nMaxFile = 4096;
    ofn.lpstrFilter = L"All files\0*.*\0";
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_EXPLORER;
    if (::GetOpenFileNameW(&ofn)) setSourcePaths({std::filesystem::path(buf)});
}

void setSourcePaths(std::vector<std::filesystem::path> paths) {
    g_chosenPaths = std::move(paths);
    std::error_code ec;
    std::wstring info = g_chosenPaths.size() > 1
        ? std::to_wstring(g_chosenPaths.size()) + L" paths"
        : (std::filesystem::is_directory(g_chosenPaths[0], ec) ? L"Folder: " : L"File: ") + g_chosenPaths[0].wstring();
    SetWindowTextW(g_srcInfo, (info + L"   (pick a process to clear)").c_str());
}

void onDrop(HDROP drop) {
    std::vector<std::filesystem::path> paths;
    UINT n = DragQueryFileW(drop, 0xFFFFFFFF, nullptr, 0);
    for (UINT i = 0; i < n; ++i) {
        std::wstring p(DragQueryFileW(drop, i, nullptr, 0) + 1, L'\0');
        p.resize(DragQueryFileW(drop, i, p.data(), (UINT)p.size()));
        paths.push_back(std::move(p));
    }
    DragFinish(drop);
    if (paths.empty()) return;
    setSourcePaths(std::move(paths));
    SetWindowTextW(g_status, L"Dropped. Hit Scan.");
}

/*--- group headers ---*/
int g_pillHot = -1;
int pillAt(POINT pt);
void copyGroup(int group);
LRESULT CALLBACK resultsSub(HWND h, UINT msg, WPARAM wp, LPARAM lp, UINT_PTR, DWORD_PTR) {
    if (msg == WM_DROPFILES) { onDrop((HDROP)wp); return 0; }
    if (msg == WM_LBUTTONDOWN || msg == WM_LBUTTONDBLCLK) {
        const int row = pillAt({GET_X_LPARAM(lp), GET_Y_LPARAM(lp)});
        if (row >= 0) { copyGroup(g_rows[row].group); return 0; }
    }
    if (msg == WM_MOUSEMOVE) {
        const int row = pillAt({GET_X_LPARAM(lp), GET_Y_LPARAM(lp)});
        if (row != g_pillHot) {
            const int old = g_pillHot; g_pillHot = row;
            for (int r : {old, row}) if (r >= 0 && r < (int)g_rows.size()) ListView_RedrawItems(h, r, r);
        }
        if (row >= 0) { TRACKMOUSEEVENT t{sizeof(t), TME_LEAVE, h, 0}; TrackMouseEvent(&t); }
    }
    if (msg == WM_MOUSELEAVE && g_pillHot >= 0) {
        const int old = g_pillHot; g_pillHot = -1;
        if (old < (int)g_rows.size()) ListView_RedrawItems(h, old, old);
    }
    if (msg == WM_SETCURSOR && g_pillHot >= 0 && LOWORD(lp) == HTCLIENT) { SetCursor(LoadCursor(nullptr, IDC_HAND)); return TRUE; }
    if (msg == WM_NOTIFY) {
        auto* cd = (NMCUSTOMDRAW*)lp;
        if (cd->hdr.code == NM_CUSTOMDRAW && cd->hdr.hwndFrom == ListView_GetHeader(h)) {
            if (cd->dwDrawStage == CDDS_PREPAINT) return CDRF_NOTIFYITEMDRAW;
            if (cd->dwDrawStage != CDDS_ITEMPREPAINT) return CDRF_DODEFAULT;
            HBRUSH b = CreateSolidBrush(kCard);
            FillRect(cd->hdc, &cd->rc, b);
            DeleteObject(b);
            wchar_t t[64] = L"";
            HDITEMW hi{};
            hi.mask = HDI_TEXT; hi.pszText = t; hi.cchTextMax = 64;
            Header_GetItem(cd->hdr.hwndFrom, (int)cd->dwItemSpec, &hi);
            HFONT of = (HFONT)SelectObject(cd->hdc, g_font);
            SetBkMode(cd->hdc, TRANSPARENT);
            SetTextColor(cd->hdc, kText2);
            RECT tr = cd->rc; tr.left += S(6);
            DrawTextW(cd->hdc, t, -1, &tr, DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);
            SelectObject(cd->hdc, of);
            HPEN pen = CreatePen(PS_SOLID, 1, kBSub), op = (HPEN)SelectObject(cd->hdc, pen);
            MoveToEx(cd->hdc, cd->rc.right - 1, cd->rc.top + S(5), nullptr);
            LineTo(cd->hdc, cd->rc.right - 1, cd->rc.bottom - S(5));
            MoveToEx(cd->hdc, cd->rc.left, cd->rc.bottom - 1, nullptr);
            LineTo(cd->hdc, cd->rc.right, cd->rc.bottom - 1);
            SelectObject(cd->hdc, op); DeleteObject(pen);
            return CDRF_SKIPDEFAULT;
        }
    }
    return DefSubclassProc(h, msg, wp, lp);
}

ur::Options gatherOptions() {
    ur::Options o;
    o.ascii = isChecked(g_ascii);
    o.utf16 = isChecked(g_utf16);
    o.base64 = isChecked(g_b64);
    o.hex = isChecked(g_hex);
    o.escaped = isChecked(g_esc);
    o.mode = isChecked(g_modeRegex) ? ur::Mode::Regex : ur::Mode::Urls;
    o.dropCrap = isChecked(g_crap);
    if (o.mode == ur::Mode::Regex) {
        if (isChecked(g_pEmail)) o.presets.push_back("email");
        if (isChecked(g_pIpv4)) o.presets.push_back("ipv4");
        if (isChecked(g_pIpv6)) o.presets.push_back("ipv6");
        if (isChecked(g_pGuid)) o.presets.push_back("guid");
        if (isChecked(g_pApi)) o.presets.push_back("apikey");
        if (isChecked(g_pPath)) o.presets.push_back("filepath");
        if (isChecked(g_pDl)) o.presets.push_back("fileurl");
        o.customRegex = narrow(controlText(g_custom).c_str());
        if (!g_activePreset.empty()) o.customLabel = g_activePreset;
        o.extraPatterns = g_profileExtras;
    }
    return o;
}

void updateModeVisibility() {
    bool regex = isChecked(g_modeRegex);
    int rx = regex ? SW_SHOW : SW_HIDE;
    for (HWND h : {g_presetLabel, g_pEmail, g_pIpv4, g_pIpv6, g_pGuid, g_pApi, g_pPath, g_pDl,
                   g_customLabel, g_custom, g_presets, g_presetPick})
        ShowWindow(h, rx);
    ShowWindow(g_urlHint, regex ? SW_HIDE : SW_SHOW);
    ShowWindow(g_crap, regex ? SW_HIDE : SW_SHOW);
}

void clearResults() {
    KillTimer(g_main, TIMER_MONITOR);
    setChecked(g_monitor, false);
    g_comparison.clear(); g_newResults.clear(); g_hasComparison = false;
    g_previousComplete.clear(); g_liveDelta = {};
    setChecked(g_newOnly, false); EnableWindow(g_newOnly, FALSE);
    g_lastResults.clear();
    g_viewResults.clear(); g_viewHits.clear();
    g_rows.clear(); g_base.clear(); g_baseHidden = 0; g_baseRows = 0;
    g_resultsPid = 0; g_resultsPids.clear();
    ListView_SetItemCountEx(g_results, 0, 0);
    SetWindowTextW(g_filter, L"");
    g_statusFull = L"Ready.";
    SetWindowTextW(g_status, L"Ready.");
    enableResultActions(false);
    InvalidateRect(g_results, nullptr, TRUE);
}

void setScanningUi(bool on) {
    g_scanning = on;
    EnableWindow(g_scan, !on);
    EnableWindow(g_settingsButton, !on);
    EnableWindow(g_pause, on);
    EnableWindow(g_cancel, on);
    for (HWND h : {g_modeUrl, g_modeRegex, g_presetPick, g_kill}) { EnableWindow(h, !on); InvalidateRect(h, nullptr, TRUE); }
    EnableWindow(g_dump, !on && !g_dumpThread.joinable()); InvalidateRect(g_dump, nullptr, TRUE);
    if (!on) { g_scanGate.setPaused(false); SetWindowTextW(g_pause, L"Pause"); }
    /* repaint now: a fast file rescan can start and finish between ordinary
       paint cycles, which left these owner-draw buttons blank mid-scan. */
    for (HWND h : {g_scan, g_pause, g_cancel})
        RedrawWindow(h, nullptr, nullptr, RDW_INVALIDATE | RDW_ERASE | RDW_UPDATENOW);
    if (on) enableResultActions(false);
}

void enableResultActions(bool on) {
    for (HWND h : {g_copy, g_save, g_editor, g_clear}) { EnableWindow(h, on); InvalidateRect(h, nullptr, TRUE); }
}

int g_srcWant = 0;   /* widest source shown, so region labels stay readable */
void populateResults(const std::vector<ur::Group>& groups) {
    g_rows.clear();
    g_pillHot = -1;
    for (int gi = 0; gi < (int)groups.size(); ++gi) {
        g_rows.push_back({gi, -1});
        for (int i = 0; i < (int)groups[gi].items.size(); ++i) g_rows.push_back({gi, i});
    }
    HDC measure = GetDC(g_results);
    HFONT oldFont = (HFONT)SelectObject(measure, g_fontMono);
    std::unordered_set<std::string> measured;
    g_srcWant = 0;
    for (const auto& g : groups) for (const auto& f : g.items) {
        if (measured.size() > 2000) break;
        if (!measured.insert(f.source).second) continue;
        std::wstring src = widen(f.source);
        SIZE sz{}; GetTextExtentPoint32W(measure, src.c_str(), (int)src.size(), &sz);
        g_srcWant = std::max(g_srcWant, (int)sz.cx);
    }
    SelectObject(measure, oldFont);
    ReleaseDC(g_results, measure);
    ListView_SetItemState(g_results, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    ListView_SetItemCountEx(g_results, (int)g_rows.size(), 0);
    if (!g_rows.empty()) ListView_EnsureVisible(g_results, 0, FALSE);
    fitColumns();
    InvalidateRect(g_results, nullptr, TRUE);
}

/* rebuild = results, ignore list or New only changed; typing in the filter
   only re-runs the text match over the folded base */
void applyResultFilter(bool rebuild = true) {
    wchar_t q[256] = L"";
    GetWindowTextW(g_filter, q, 256);
    std::string query = lower(narrow(q));
    g_viewResults.clear();
    if (rebuild) {
        const auto& visible = isChecked(g_newOnly) && g_hasComparison ? g_newResults : g_lastResults;
        g_base = visible;
        g_baseHidden = 0;
        g_baseRows = ur::countFindings(ur::foldDuplicates(g_base));
        if (isChecked(g_ignoreChip) && !g_ignore.empty()) {     /* hidden counted in rows, like the rest of the status */
            g_base = ur::filterIgnored(g_base, g_ignore);
            const std::size_t rows = ur::countFindings(ur::foldDuplicates(g_base));
            g_baseHidden = g_baseRows - rows;
            g_baseRows = rows;
        }
    }
    const std::size_t hidden = g_baseHidden;
    g_viewHits.clear();
    for (const auto& g : g_base) {
        if (query.empty() || lower(g.name).find(query) != std::string::npos) { g_viewHits.push_back(g); continue; }
        ur::Group hit;
        hit.name = g.name;
        for (const auto& f : g.items)
            if (lower(f.value).find(query) != std::string::npos ||
                lower(f.source).find(query) != std::string::npos ||
                lower(ur::encName(f.enc)).find(query) != std::string::npos)
                hit.items.push_back(f);
        if (!hit.items.empty()) g_viewHits.push_back(std::move(hit));
    }
    g_viewResults = ur::foldDuplicates(g_viewHits);     /* every hit is matched, then folded for the list */
    populateResults(g_viewResults);
    enableResultActions(!g_viewResults.empty());
    if (query.empty() && !isChecked(g_newOnly) && !hidden) { SetWindowTextW(g_status, g_statusFull.c_str()); return; }
    std::wstring why;
    auto add = [&](const std::wstring& w) { why += (why.empty() ? L"" : L", ") + w; };
    if (isChecked(g_newOnly)) add(L"new since previous complete scan");
    if (!query.empty()) add(L"filtered");
    if (hidden) add(std::to_wstring(hidden) + L" hidden by ignore list");
    wchar_t msg[256];
    _snwprintf_s(msg, _TRUNCATE, L"%zu of %zu results   (%s)",
                 ur::countFindings(g_viewResults), g_baseRows, why.c_str());
    SetWindowTextW(g_status, msg);
}

void onDone(std::vector<ur::Group>* groups) {
    if (g_scanThread.joinable()) g_scanThread.join();
    KillTimer(g_main, TIMER_PROGRESS);
    g_lastResults = std::move(*groups);
    delete groups;
    ur::resolveDownloadHosts(g_lastResults);
    const bool complete = !g_cancelFlag && g_scanError.empty() && !g_scanDenied &&
                          !g_scanDeniedFiles && !g_progress.skipped;
    g_hasComparison = complete && g_comparison.matches(g_scanContext);
    g_newResults = g_hasComparison ? g_comparison.added(g_lastResults) : std::vector<ur::Group>{};
    g_liveDelta = g_hasComparison ? ur::compareSessions(g_previousComplete, g_lastResults) : ur::SessionDelta{};
    if (complete) { g_comparison.remember(g_scanContext, g_lastResults); g_previousComplete = g_lastResults; }
    if (!g_hasComparison) setChecked(g_newOnly, false);
    EnableWindow(g_newOnly, g_hasComparison);
    g_resultsPid = (g_scanPid && !g_scanDenied) ? g_scanPid : 0;
    g_resultsPids = g_scanDenied ? std::vector<uint32_t>{} : g_scanPids;
    wchar_t msg[256];
    const std::size_t hits = ur::countFindings(g_lastResults), shown = ur::countFindings(ur::foldDuplicates(g_lastResults));
    _snwprintf_s(msg, _TRUNCATE, L"%zu results in %zu groups%s, sorted Z to A   (%.2f s)%s",
                 shown, g_lastResults.size(),
                 hits > shown ? (L" (" + std::to_wstring(hits) + L" hits)").c_str() : L"",
                 g_elapsedMs.load() / 1000.0, g_cancelFlag ? L"  (cancelled)" : L"");
    g_statusFull = msg;
    if (!g_scanError.empty()) g_statusFull = L"Scan failed: " + widen(g_scanError);
    else if (!g_cancelFlag && !g_scanDenied && !g_scanDeniedFiles && !g_progress.skipped)
        g_statusFull = L"100.0% - " + g_statusFull;
    if (g_progress.skipped)
        g_statusFull += L" - " + std::to_wstring(g_progress.skipped.load()) + L" bytes unreadable/changed";
    if (!g_scanPids.empty()) {
        g_statusFull += L" - " + std::to_wstring(g_scanPids.size()) + L" processes";
        if (g_scanTargetsDenied && !g_scanDenied)
            g_statusFull += L", " + std::to_wstring(g_scanTargetsDenied.load()) + L" could not be opened";
    }
    if (g_hasComparison) g_statusFull += L" - " + std::to_wstring(ur::countFindings(g_liveDelta.added)) +
        L" added, " + std::to_wstring(ur::countFindings(g_liveDelta.removed)) +
        L" removed, " + std::to_wstring(ur::countFindings(g_liveDelta.unchanged)) + L" unchanged";
    applyResultFilter();
    setScanningUi(false);
    if (complete && isChecked(g_monitor)) {
        unsigned seconds = (unsigned)std::wcstoul(controlText(g_monitorInterval).c_str(), nullptr, 10);
        SetTimer(g_main, TIMER_MONITOR, std::clamp(seconds, 1u, 3600u) * 1000u, nullptr);
    }
    if (g_scanDenied) {
        if (g_scanNeedsElev && !g_elevated)
            MessageBoxW(g_main, L"This process runs with higher rights. Close StringRipper and start it again "
                                L"as administrator (right-click the exe, Run as administrator), then scan it again.",
                        L"StringRipper", MB_OK | MB_ICONINFORMATION);
        else
            MessageBoxW(g_main, L"Could not open that process for reading.", L"StringRipper", MB_ICONWARNING);
    } else if (g_scanDeniedFiles) {
        if (!g_elevated)
            MessageBoxW(g_main, L"Some of that could not be read. Close StringRipper and start it again "
                                L"as administrator (right-click the exe, Run as administrator), then scan again.",
                        L"StringRipper", MB_OK | MB_ICONINFORMATION);
        else
            MessageBoxW(g_main, L"Some of that could not be read, even as administrator.", L"StringRipper", MB_ICONWARNING);
    }
}

/* URL and regex mode keep their own last results and filter; the inactive mode's wait here */
bool g_filterQuiet = false;
void switchMode(bool regex) {
    if (isChecked(g_modeRegex) != regex && !g_scanning) {
        KillTimer(g_main, TIMER_MONITOR); setChecked(g_monitor, false);
        std::swap(g_lastResults, g_otherSlot.last); std::swap(g_newResults, g_otherSlot.fresh);
        std::swap(g_previousComplete, g_otherSlot.previous); std::swap(g_comparison, g_otherSlot.comparison);
        std::swap(g_liveDelta, g_otherSlot.delta); std::swap(g_scanContext, g_otherSlot.context);
        std::swap(g_hasComparison, g_otherSlot.hasComparison); std::swap(g_statusFull, g_otherSlot.status);
        std::swap(g_resultsPid, g_otherSlot.pid); std::swap(g_resultsPids, g_otherSlot.pids);
        std::wstring mine = controlText(g_filter);
        g_filterQuiet = true; SetWindowTextW(g_filter, g_otherSlot.filter.c_str()); g_filterQuiet = false;
        g_otherSlot.filter = std::move(mine);
        setChecked(g_modeUrl, !regex); setChecked(g_modeRegex, regex);
        g_lastMode = regex ? ur::Mode::Regex : ur::Mode::Urls;
        setChecked(g_newOnly, false); EnableWindow(g_newOnly, g_hasComparison);
        applyResultFilter();
        enableResultActions(!g_viewResults.empty());
    }
    updateModeVisibility();
    relayout(g_main);
}
void setRegexMode() { switchMode(true); }
void fillPresetPick() {
    SendMessageW(g_presetPick, CB_RESETCONTENT, 0, 0);
    SendMessageW(g_presetPick, CB_ADDSTRING, 0, (LPARAM)(g_userPresets.empty() ? L"No user presets" : L"Pick a preset..."));
    int active = 0;
    for (int i = 0; i < (int)g_userPresets.size(); ++i) {
        SendMessageW(g_presetPick, CB_ADDSTRING, 0, (LPARAM)widen(g_userPresets[i].name).c_str());
        if (!g_activePreset.empty() && g_userPresets[i].name == g_activePreset) active = i + 1;
    }
    SendMessageW(g_presetPick, CB_SETCURSEL, active, 0);
}

void doScan() {
    KillTimer(g_main, TIMER_MONITOR);
    if (g_fileSelection.rangeEnd && g_fileSelection.rangeEnd <= g_fileSelection.rangeStart) {
        MessageBoxW(g_main, L"Range end must be greater than range start.", L"Scan settings", MB_ICONWARNING);
        return;
    }
    if (g_scanning) return;
    ur::Options o = gatherOptions();
    g_lastMode = o.mode;
    std::shared_ptr<ur::Detector> detector;
    try { detector = std::make_shared<ur::Detector>(o); }
    catch (const ur::RegexError& e) {
        MessageBoxW(g_main, widen(e.what()).c_str(), L"Pattern error", MB_ICONERROR);
        return;
    }

    uint32_t pid = 0;
    std::string procName;
    std::vector<uint32_t> pids;
    std::vector<std::filesystem::path> paths = g_chosenPaths;
    if (paths.empty()) {
        int sel = (int)SendMessageW(g_source, CB_GETCURSEL, 0, 0);
        if (sel >= 0 && sel < (int)g_procsView.size()) { pid = g_procsView[sel].pid; procName = g_procsView[sel].name; }
    }
    if (pid && isChecked(g_allInst))
        for (const auto& p : g_procsAll) if (_stricmp(p.name.c_str(), procName.c_str()) == 0) pids.push_back(p.pid);
    if (pids.size() < 2) pids.clear();
    if (!pid && paths.empty()) {
        MessageBoxW(g_main, L"Choose a process, or drop files on the window.", L"StringRipper", MB_ICONINFORMATION);
        return;
    }

    g_cancelFlag = false;
    g_scanGate.setPaused(false);
    std::string source = pids.empty() ? "pid:" + std::to_string(pid) : "name:" + lower(procName);
    if (!paths.empty()) {
        std::vector<std::string> names;
        for (const auto& p : paths) {
            std::error_code ec;
            auto absolute = std::filesystem::absolute(p, ec);
            names.push_back(ur::pathUtf8((ec ? p : absolute).lexically_normal()));
        }
        std::sort(names.begin(), names.end());
        source = "files:";
        for (const auto& n : names) source += std::to_string(n.size()) + ":" + n;
    }
    g_scanContext = ur::comparisonContext(source, o) + ur::selectionContext(g_fileSelection);
    g_scanPid = pids.empty() ? pid : 0;
    g_scanPids = pids; g_scanTargetsDenied = 0;
    g_progress.reset();
    g_scanError.clear();
    setScanningUi(true);
    SetWindowTextW(g_filter, L"");
    SetWindowTextW(g_status, L"Preparing scan...");
    SetTimer(g_main, TIMER_PROGRESS, 120, nullptr);

    const auto selection = g_fileSelection;
    g_scanThread = std::thread([detector, pid, pids, paths, selection]() {
        auto* result = new std::vector<ur::Group>();
        bool denied = false, needsElev = false, fdenied = false;
        auto t0 = std::chrono::steady_clock::now();
        try {
            auto cancel = [] { return g_cancelFlag.load(); };
            auto pause = [cancel] { g_scanGate.wait(cancel); };
            ur::DriverLimits limits;
            limits.rangeStart = selection.rangeStart; limits.rangeEnd = selection.rangeEnd;
            if (!pids.empty()) {
                auto scan = ur::scanProcesses(*detector, pids, true, cancel, &g_progress, limits, pause);
                *result = std::move(scan.groups);
                g_scanTargetsDenied = scan.denied;
                denied = scan.opened == 0; needsElev = scan.needsElevation;
            }
            else if (pid) *result = ur::scanProcess(*detector, pid, cancel, denied, needsElev, &g_progress, limits, pause);
            else *result = ur::scanPaths(*detector, paths, &fdenied, &g_progress, cancel, selection, pause);
        } catch (const std::exception& e) { g_scanError = e.what(); }
        catch (...) { g_scanError = "Unknown error"; }
        g_elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0).count();
        g_scanDenied = denied;
        g_scanNeedsElev = needsElev;
        g_scanDeniedFiles = fdenied;
        PostMessageW(g_main, WM_APP_DONE, 0, (LPARAM)result);
    });
}

enum : int { WS_SESSIONS = 6000, WS_NAME, WS_SAVE_SESSION, WS_OPEN_SESSION, WS_COMPARE,
             WS_JOBS, WS_SAVE_JOB, WS_RUN_JOB, WS_ADDED, WS_REMOVED, WS_STATUS, WS_CLOSE,
             WS_FAVORITES, WS_ADD_FAVORITE, WS_USE_FAVORITE, WS_REMOVE_FAVORITE };
HWND g_ws = nullptr, g_wsSessions, g_wsName, g_wsJobs, g_wsFavorites, g_wsAdded, g_wsRemoved, g_wsStatus;
std::vector<ur::Session> g_wsIndex;
std::vector<std::pair<std::string, std::string>> g_wsFavoriteIndex;

/* data lives next to the exe, so the folder is the whole install. A folder we
   may not write to (Program Files) falls back to %LOCALAPPDATA%\StringRipper
   under the old names. The first portable start copies old app-data files over
   once and leaves the originals. */
std::filesystem::path oldDataDir() {
    wchar_t base[32768]{};
    DWORD n = GetEnvironmentVariableW(L"LOCALAPPDATA", base, 32768);
    return n && n < 32768 ? std::filesystem::path(base) / L"StringRipper" : std::filesystem::path();
}
bool writableDir(const std::filesystem::path& dir) {
    auto probe = dir / (L"StringRipper.probe." + std::to_wstring(GetCurrentProcessId()));
    HANDLE h = CreateFileW(probe.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                           FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    CloseHandle(h);
    return true;
}
/* settings live in data\ beside the exe, so the folder is the whole install; a
   folder we may not write to falls back to %LOCALAPPDATA%\StringRipper\data.
   Older layouts move in once: 1.3.0 files beside the exe and 1.2.x files in
   app data are moved, 1.2.x app data feeding a portable start is copied. */
std::filesystem::path appDataDir() {
    static const std::filesystem::path dir = [] {
        wchar_t exe[MAX_PATH]{}; GetModuleFileNameW(nullptr, exe, MAX_PATH);
        auto here = std::filesystem::path(exe).parent_path(), old = oldDataDir();
        std::error_code ec;
        auto adopt = [&](const std::filesystem::path& from, const std::filesystem::path& to, bool move) {
            if (std::filesystem::exists(to, ec) || !std::filesystem::exists(from, ec)) return;
            if (move) { std::filesystem::rename(from, to, ec); if (!ec) return; ec.clear(); }
            std::filesystem::copy_file(from, to, ec);
        };
        const bool portable = writableDir(here);
        if (!portable && old.empty()) return here;
        auto data = (portable ? here : old) / L"data";
        std::filesystem::create_directories(data, ec);
        /* a db travels with its journal files, and only from one place: 1.3.0 beside the exe first */
        const wchar_t* db[] = {L"workspace.sqlite-journal", L"workspace.sqlite-wal", L"workspace.sqlite-shm", L"workspace.sqlite"};
        if (portable && !std::filesystem::exists(data / L"workspace.sqlite", ec))
            for (const wchar_t* n : db) adopt(here / (std::wstring(L"StringRipper.") + n), data / n, true);
        if (!old.empty() && !std::filesystem::exists(data / L"workspace.sqlite", ec))
            for (const wchar_t* n : db) adopt(old / n, data / n, !portable);
        if (portable) adopt(here / L"StringRipper.update.ini", data / L"update.ini", true);
        if (!old.empty()) adopt(old / L"update.ini", data / L"update.ini", !portable);
        for (const wchar_t* n : {L"regex-user-presets.ini", L"regex-user-presets.ini.bak"})
            adopt(here / n, data / n, portable);
        g_portable = portable;
        return data;
    }();
    return dir;
}
std::filesystem::path dataFile(const wchar_t* name) { return appDataDir() / name; }
std::filesystem::path workspaceDatabase() { return dataFile(L"workspace.sqlite"); }

void loadIgnoreRules() {
    try { ur::SessionStore db(workspaceDatabase()); g_ignoreLines = db.ignoreRules(); }
    catch (const std::exception&) { g_ignoreLines.clear(); }
    g_ignore = ur::IgnoreRules::parse(g_ignoreLines);
}
void saveIgnoreRules() {
    try { ur::SessionStore db(workspaceDatabase()); db.setIgnoreRules(g_ignoreLines); }
    catch (const std::exception& e) { MessageBoxW(g_main, widen(e.what()).c_str(), L"Ignore list", MB_ICONERROR); }
    g_ignore = ur::IgnoreRules::parse(g_ignoreLines);
    applyResultFilter();
}

enum : int { IG_TEXT = 6300, IG_SAVE, IG_CANCEL };
HWND g_ig = nullptr, g_igText;
LRESULT CALLBACK IgnoreProc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        darkTitle(h);
        peCtl(h, L"STATIC", L"One rule per line. microsoft.com hides that host and its subdomains,", 0, 0, 16, 12, 560, 20);
        peCtl(h, L"STATIC", L"*telemetry* hides values matching the pattern, =value hides exactly that value.", 0, 0, 16, 32, 560, 20);
        std::string text;
        for (const auto& line : g_ignoreLines) text += line + "\r\n";
        g_igText = peCtl(h, L"EDIT", widen(text).c_str(), IG_TEXT,
            ES_MULTILINE | ES_AUTOVSCROLL | ES_WANTRETURN | WS_BORDER | WS_VSCROLL, 16, 62, 560, 296);
        peCtl(h, L"BUTTON", L"Save", IG_SAVE, BS_DEFPUSHBUTTON, 364, 372, 102, 30);
        peCtl(h, L"BUTTON", L"Cancel", IG_CANCEL, BS_PUSHBUTTON, 474, 372, 102, 30);
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == IG_SAVE) {
            std::istringstream in(narrow(controlText(g_igText).c_str()));
            g_ignoreLines.clear();
            for (std::string line; std::getline(in, line);) {
                if (!line.empty() && line.back() == '\r') line.pop_back();
                if (line.find_first_not_of(" \t") != std::string::npos) g_ignoreLines.push_back(line);
            }
            saveIgnoreRules();
            DestroyWindow(h);
            return 0;
        }
        if (LOWORD(wp) == IG_CANCEL || LOWORD(wp) == IDCANCEL) { DestroyWindow(h); return 0; }
        break;
    case WM_CTLCOLORSTATIC: case WM_CTLCOLORBTN: {
        HDC dc = (HDC)wp; SetTextColor(dc, kText); SetBkColor(dc, kBg); return (LRESULT)g_bgBrush;
    }
    case WM_CTLCOLOREDIT: {
        HDC dc = (HDC)wp; SetTextColor(dc, kText); SetBkColor(dc, kBg2); return (LRESULT)g_bg2Brush;
    }
    case WM_ERASEBKGND: { RECT r; GetClientRect(h, &r); FillRect((HDC)wp, &r, g_bgBrush); return 1; }
    case WM_CLOSE: DestroyWindow(h); return 0;
    case WM_DESTROY: g_ig = nullptr; EnableWindow(g_main, TRUE); SetForegroundWindow(g_main); return 0;
    }
    return DefWindowProcW(h, msg, wp, lp);
}
void showIgnoreEditor() {
    if (g_ig) { SetForegroundWindow(g_ig); return; }
    WNDCLASSEXW wc{sizeof(wc)};
    wc.lpfnWndProc = IgnoreProc; wc.hInstance = GetModuleHandleW(nullptr);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW); wc.hbrBackground = g_bgBrush; wc.lpszClassName = L"StringRipperIgnoreList";
    RegisterClassExW(&wc);
    RECT r{0, 0, S(592), S(416)};
    AdjustWindowRectEx(&r, WS_CAPTION | WS_SYSMENU, FALSE, WS_EX_DLGMODALFRAME);
    EnableWindow(g_main, FALSE);
    g_ig = CreateWindowExW(WS_EX_DLGMODALFRAME, wc.lpszClassName, L"Ignore list", WS_CAPTION | WS_SYSMENU,
        CW_USEDEFAULT, CW_USEDEFAULT, r.right - r.left, r.bottom - r.top, g_main, nullptr, wc.hInstance, nullptr);
    if (!g_ig) { EnableWindow(g_main, TRUE); return; }
    ShowWindow(g_ig, SW_SHOW); UpdateWindow(g_ig);
}
void wsError(HWND h, const std::exception& e) {
    SetWindowTextW(g_wsStatus, widen(e.what()).c_str());
    MessageBoxW(h, widen(e.what()).c_str(), L"Workspace", MB_ICONERROR);
}
void wsRefresh() {
    ur::SessionStore db(workspaceDatabase());
    g_wsIndex = db.listSessions();
    SendMessageW(g_wsSessions, LB_RESETCONTENT, 0, 0);
    for (const auto& s : g_wsIndex) {
        auto label = widen(s.created + "  |  " + s.name + "  |  " + s.source);
        SendMessageW(g_wsSessions, LB_ADDSTRING, 0, (LPARAM)label.c_str());
    }
    SendMessageW(g_wsJobs, LB_RESETCONTENT, 0, 0);
    for (const auto& name : db.listJobs())
        SendMessageW(g_wsJobs, LB_ADDSTRING, 0, (LPARAM)widen(name).c_str());
    g_wsFavoriteIndex.clear();
    SendMessageW(g_wsFavorites, LB_RESETCONTENT, 0, 0);
    for (const auto& kind : {"process", "path", "source"})
        for (const auto& target : db.favorites(kind)) {
            g_wsFavoriteIndex.emplace_back(kind, target);
            auto label = widen(std::string("[") + kind + "] " + target);
            SendMessageW(g_wsFavorites, LB_ADDSTRING, 0, (LPARAM)label.c_str());
        }
    SetWindowTextW(g_wsStatus, (std::to_wstring(g_wsIndex.size()) + L" saved sessions").c_str());
}
std::vector<int> wsSelectedSessions() {
    int count = (int)SendMessageW(g_wsSessions, LB_GETSELCOUNT, 0, 0);
    if (count <= 0) return {};
    std::vector<int> indices(count);
    SendMessageW(g_wsSessions, LB_GETSELITEMS, count, (LPARAM)indices.data());
    return indices;
}
void wsApplyOptions(const ur::Options& o) {
    g_profileExtras = o.extraPatterns;
    g_profileNames.clear();
    setChecked(g_modeUrl, o.mode == ur::Mode::Urls);
    setChecked(g_modeRegex, o.mode == ur::Mode::Regex);
    setChecked(g_ascii, o.ascii); setChecked(g_utf16, o.utf16);
    setChecked(g_b64, o.base64); setChecked(g_hex, o.hex); setChecked(g_esc, o.escaped);
    auto has = [&](const char* p) { return std::find(o.presets.begin(), o.presets.end(), p) != o.presets.end(); };
    setChecked(g_pEmail, has("email")); setChecked(g_pIpv4, has("ipv4"));
    setChecked(g_pIpv6, has("ipv6")); setChecked(g_pGuid, has("guid"));
    setChecked(g_pApi, has("apikey")); setChecked(g_pPath, has("filepath"));
    setChecked(g_pDl, has("fileurl")); setChecked(g_crap, o.dropCrap);
    SetWindowTextW(g_custom, widen(o.customRegex).c_str());
    SetWindowTextW(g_presets, o.extraPatterns.empty() ? L"User presets..." : L"Profile loaded...");
    updateModeVisibility(); relayout(g_main);
}
LRESULT CALLBACK WorkspaceProc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE:
        darkTitle(h);
        peCtl(h, L"STATIC", L"Saved sessions (select two to compare)", 0, 0, 14, 12, 620, 22);
        g_wsSessions = peCtl(h, L"LISTBOX", L"", WS_SESSIONS,
            LBS_EXTENDEDSEL | WS_BORDER | WS_VSCROLL | WS_HSCROLL, 14, 38, 626, 132);
        peCtl(h, L"STATIC", L"Name", 0, 0, 14, 180, 70, 22);
        g_wsName = peCtl(h, L"EDIT", L"My scan", WS_NAME, ES_AUTOHSCROLL | WS_BORDER, 82, 177, 268, 28);
        SendMessageW(g_wsName, EM_LIMITTEXT, 200, 0);  // used as both a session and a job name
        peCtl(h, L"BUTTON", L"Save current", WS_SAVE_SESSION, BS_PUSHBUTTON, 360, 177, 122, 28);
        peCtl(h, L"BUTTON", L"Open", WS_OPEN_SESSION, BS_PUSHBUTTON, 490, 177, 72, 28);
        peCtl(h, L"BUTTON", L"Compare", WS_COMPARE, BS_PUSHBUTTON, 570, 177, 70, 28);
        peCtl(h, L"STATIC", L"Added / current", 0, 0, 14, 220, 300, 22);
        peCtl(h, L"STATIC", L"Removed / previous", 0, 0, 333, 220, 300, 22);
        g_wsAdded = peCtl(h, L"EDIT", L"", WS_ADDED,
            ES_MULTILINE | ES_READONLY | WS_BORDER | WS_VSCROLL, 14, 246, 307, 175);
        g_wsRemoved = peCtl(h, L"EDIT", L"", WS_REMOVED,
            ES_MULTILINE | ES_READONLY | WS_BORDER | WS_VSCROLL, 333, 246, 307, 175);
        peCtl(h, L"STATIC", L"Reusable jobs", 0, 0, 14, 437, 620, 22);
        g_wsJobs = peCtl(h, L"LISTBOX", L"", WS_JOBS, LBS_NOTIFY | WS_BORDER | WS_VSCROLL,
                         14, 464, 416, 85);
        peCtl(h, L"BUTTON", L"Save job", WS_SAVE_JOB, BS_PUSHBUTTON, 442, 464, 198, 28);
        peCtl(h, L"BUTTON", L"Run selected", WS_RUN_JOB, BS_PUSHBUTTON, 442, 502, 198, 28);
        peCtl(h, L"STATIC", L"Favorite sources", 0, 0, 14, 562, 620, 22);
        g_wsFavorites = peCtl(h, L"LISTBOX", L"", WS_FAVORITES, LBS_NOTIFY | WS_BORDER | WS_VSCROLL,
                              14, 588, 416, 84);
        peCtl(h, L"BUTTON", L"Add current", WS_ADD_FAVORITE, BS_PUSHBUTTON, 442, 588, 198, 25);
        peCtl(h, L"BUTTON", L"Use selected", WS_USE_FAVORITE, BS_PUSHBUTTON, 442, 617, 95, 25);
        peCtl(h, L"BUTTON", L"Remove", WS_REMOVE_FAVORITE, BS_PUSHBUTTON, 545, 617, 95, 25);
        g_wsStatus = peCtl(h, L"STATIC", L"", WS_STATUS, 0, 14, 684, 490, 22);
        peCtl(h, L"BUTTON", L"Close", WS_CLOSE, BS_PUSHBUTTON, 530, 679, 110, 30);
        try { wsRefresh(); } catch (const std::exception& e) { wsError(h, e); }
        return 0;
    case WM_COMMAND:
        try {
            const int id = LOWORD(wp);
            if (id == WS_SAVE_SESSION) {
                if (g_lastResults.empty()) throw std::runtime_error("Scan first before saving a session");
                auto name = narrow(controlText(g_wsName).c_str());
                if (name.empty()) throw std::runtime_error("Enter a session name");
                std::string source = g_resultsPid ? "pid " + std::to_string(g_resultsPid) : "files";
                if (!g_resultsPids.empty()) { source = "pids"; for (uint32_t p : g_resultsPids) source += " " + std::to_string(p); }
                ur::SessionStore db(workspaceDatabase());
                db.saveSession({0, name, source, "", g_lastResults}); wsRefresh();
            } else if (id == WS_OPEN_SESSION) {
                auto selected = wsSelectedSessions();
                if (selected.size() != 1) throw std::runtime_error("Select exactly one session to open");
                ur::SessionStore db(workspaceDatabase());
                auto session = db.loadSession(g_wsIndex[selected[0]].id);
                g_lastResults = std::move(session.groups);
                g_resultsPid = 0; g_resultsPids.clear();
                g_comparison.clear(); g_hasComparison = false; g_newResults.clear();
                setChecked(g_newOnly, false); EnableWindow(g_newOnly, FALSE);
                g_statusFull = L"Opened session: " + widen(session.name);
                applyResultFilter();
                DestroyWindow(h);
            } else if (id == WS_COMPARE) {
                auto selected = wsSelectedSessions();
                if (selected.size() != 2) throw std::runtime_error("Select exactly two sessions");
                ur::SessionStore db(workspaceDatabase());
                auto a = db.loadSession(g_wsIndex[selected[1]].id);
                auto b = db.loadSession(g_wsIndex[selected[0]].id);
                auto delta = ur::compareSessions(a.groups, b.groups);
                auto display = [](const std::vector<ur::Group>& groups) {
                    auto s = ur::exportResults(groups, "txt");
                    if (s.size() > 100000) s.resize(100000);
                    return widen(s);
                };
                SetWindowTextW(g_wsAdded, display(delta.added).c_str());
                SetWindowTextW(g_wsRemoved, display(delta.removed).c_str());
                SetWindowTextW(g_wsStatus, (std::to_wstring(ur::countFindings(delta.added)) +
                    L" added, " + std::to_wstring(ur::countFindings(delta.removed)) + L" removed, " +
                    std::to_wstring(ur::countFindings(delta.unchanged)) + L" unchanged").c_str());
            } else if (id == WS_SAVE_JOB) {
                auto name = narrow(controlText(g_wsName).c_str());
                if (name.empty()) throw std::runtime_error("Enter a job name");
                ur::ScanJob job; job.name = name; job.options = gatherOptions();
                job.files = g_fileSelection;
                job.monitorSeconds = isChecked(g_monitor) ?
                    std::clamp((unsigned)std::wcstoul(controlText(g_monitorInterval).c_str(), nullptr, 10), 1u, 3600u) : 0;
                job.sources = g_chosenPaths;
                if (job.sources.empty()) {
                    int sel = (int)SendMessageW(g_source, CB_GETCURSEL, 0, 0);
                    if (sel >= 0 && sel < (int)g_procsView.size()) {
                        job.pid = g_procsView[sel].pid;
                        job.processName = g_procsView[sel].name;
                    }
                }
                if (!job.pid && job.sources.empty()) throw std::runtime_error("Choose a source first");
                ur::SessionStore db(workspaceDatabase()); db.saveJob(job); wsRefresh();
            } else if (id == WS_RUN_JOB) {
                int selected = (int)SendMessageW(g_wsJobs, LB_GETCURSEL, 0, 0);
                if (selected < 0) throw std::runtime_error("Select a job");
                int len = (int)SendMessageW(g_wsJobs, LB_GETTEXTLEN, selected, 0);
                if (len == LB_ERR) throw std::runtime_error("Could not read the job name");
                std::wstring name(static_cast<std::size_t>(len) + 1, L'\0');
                SendMessageW(g_wsJobs, LB_GETTEXT, selected, (LPARAM)name.data());
                name.resize(static_cast<std::size_t>(len));
                ur::SessionStore db(workspaceDatabase());
                auto job = db.loadJob(narrow(name.c_str()));
                if (!job) throw std::runtime_error("Job is missing or invalid");
                wsApplyOptions(job->options);
                g_fileSelection = job->files;
                setChecked(g_monitor, job->monitorSeconds != 0);
                SetWindowTextW(g_monitorInterval, std::to_wstring(job->monitorSeconds ? job->monitorSeconds : 5).c_str());
                if (!job->sources.empty()) setSourcePaths(job->sources);
                else if (!job->processName.empty()) {
                    refreshProcesses();
                    std::vector<std::pair<uint32_t, std::string>> active;
                    for (const auto& process : g_procsAll) active.emplace_back(process.pid, process.name);
                    const auto resolved = ur::resolveProcessJob(*job, active);
                    if (!resolved)
                        throw std::runtime_error("Process is not running: " + job->processName);
                    g_chosenPaths.clear();
                    SetWindowTextW(g_search, L""); applyProcFilter();
                    if (!selectPid(*resolved)) throw std::runtime_error("Could not select process: " + job->processName);
                } else if (job->pid) {
                    throw std::runtime_error("Old process job has no process name; save it again");
                } else throw std::runtime_error("Job has no source");
                DestroyWindow(h);
                PostMessageW(g_main, WM_COMMAND, ID_SCAN, 0);
            } else if (id == WS_ADD_FAVORITE) {
                ur::SessionStore db(workspaceDatabase());
                if (!g_chosenPaths.empty()) {
                    for (const auto& path : g_chosenPaths) {
                        const auto text = ur::pathUtf8(path);
                        if (text.empty()) throw std::runtime_error("Cannot convert favorite path to UTF-8");
                        db.setFavorite("path", text, true);
                    }
                } else {
                    int sel = (int)SendMessageW(g_source, CB_GETCURSEL, 0, 0);
                    if (sel < 0 || sel >= (int)g_procsView.size())
                        throw std::runtime_error("Choose a process or file source first");
                    db.setFavorite("process", g_procsView[sel].name, true);
                }
                wsRefresh();
            } else if (id == WS_USE_FAVORITE || id == WS_REMOVE_FAVORITE) {
                int selected = (int)SendMessageW(g_wsFavorites, LB_GETCURSEL, 0, 0);
                if (selected < 0 || selected >= (int)g_wsFavoriteIndex.size())
                    throw std::runtime_error("Select a favorite");
                const auto [kind, target] = g_wsFavoriteIndex[selected];
                if (id == WS_REMOVE_FAVORITE) {
                    ur::SessionStore db(workspaceDatabase());
                    db.setFavorite(kind, target, false); wsRefresh();
                } else if (kind == "process") {
                    refreshProcesses();
                    auto it = std::find_if(g_procsAll.begin(), g_procsAll.end(),
                        [&](const fxchain::RipProcess& p) { return p.name == target; });
                    if (it == g_procsAll.end()) throw std::runtime_error("Favorite process is not running");
                    SetWindowTextW(g_search, L""); applyProcFilter();
                    if (!selectPid(it->pid)) throw std::runtime_error("Could not select favorite process");
                    g_chosenPaths.clear();
                    DestroyWindow(h);
                } else {
                    auto path = ur::pathFromUtf8(target);
                    if (!path || !std::filesystem::exists(*path)) throw std::runtime_error("Favorite path no longer exists");
                    setSourcePaths({*path});
                    DestroyWindow(h);
                }
            } else if (id == WS_CLOSE || id == IDCANCEL) DestroyWindow(h);
        } catch (const std::exception& e) { wsError(h, e); }
        return 0;
    case WM_CTLCOLORSTATIC: case WM_CTLCOLORBTN: {
        HDC dc = (HDC)wp; SetTextColor(dc, kText); SetBkColor(dc, kBg); return (LRESULT)g_bgBrush;
    }
    case WM_CTLCOLOREDIT: case WM_CTLCOLORLISTBOX: {
        HDC dc = (HDC)wp; SetTextColor(dc, kText); SetBkColor(dc, kBg2); return (LRESULT)g_bg2Brush;
    }
    case WM_ERASEBKGND: { RECT r; GetClientRect(h, &r); FillRect((HDC)wp, &r, g_bgBrush); return 1; }
    case WM_CLOSE: DestroyWindow(h); return 0;
    case WM_DESTROY: g_ws = nullptr; EnableWindow(g_main, TRUE); SetForegroundWindow(g_main); return 0;
    }
    return DefWindowProcW(h, msg, wp, lp);
}
void showWorkspace() {
    if (g_ws) { SetForegroundWindow(g_ws); return; }
    WNDCLASSEXW wc{sizeof(wc)}; wc.lpfnWndProc = WorkspaceProc;
    wc.hInstance = GetModuleHandleW(nullptr); wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = g_bgBrush; wc.lpszClassName = L"StringRipperWorkspace";
    RegisterClassExW(&wc);
    RECT r{0, 0, S(654), S(720)};
    AdjustWindowRectEx(&r, WS_CAPTION | WS_SYSMENU, FALSE, WS_EX_DLGMODALFRAME);
    EnableWindow(g_main, FALSE);
    g_ws = CreateWindowExW(WS_EX_DLGMODALFRAME, wc.lpszClassName, L"StringRipper Workspace",
        WS_CAPTION | WS_SYSMENU, CW_USEDEFAULT, CW_USEDEFAULT, r.right-r.left, r.bottom-r.top,
        g_main, nullptr, wc.hInstance, nullptr);
    if (!g_ws) { EnableWindow(g_main, TRUE); return; }
    ShowWindow(g_ws, SW_SHOW); UpdateWindow(g_ws);
}

HWND g_dashboardWindow = nullptr;
LRESULT CALLBACK DashboardProc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        darkTitle(h);
        peCtl(h, L"STATIC", L"Findings by pattern, source and encoding", 0, 0, 16, 14, 560, 24);
        auto summary = widen(ur::dashboardText(ur::summarizeResults(g_viewHits)));
        peCtl(h, L"EDIT", summary.c_str(), 0,
              ES_MULTILINE | ES_READONLY | WS_BORDER | WS_VSCROLL | WS_HSCROLL,
              16, 42, 568, 408);
        peCtl(h, L"BUTTON", L"Close", IDCANCEL, BS_DEFPUSHBUTTON, 480, 464, 104, 30);
        return 0;
    }
    case WM_COMMAND: if (LOWORD(wp) == IDCANCEL) { DestroyWindow(h); return 0; } break;
    case WM_CTLCOLORSTATIC: case WM_CTLCOLORBTN: {
        HDC dc = (HDC)wp; SetTextColor(dc, kText); SetBkColor(dc, kBg); return (LRESULT)g_bgBrush;
    }
    case WM_CTLCOLOREDIT: {
        HDC dc = (HDC)wp; SetTextColor(dc, kText); SetBkColor(dc, kBg2); return (LRESULT)g_bg2Brush;
    }
    case WM_ERASEBKGND: { RECT r; GetClientRect(h, &r); FillRect((HDC)wp, &r, g_bgBrush); return 1; }
    case WM_CLOSE: DestroyWindow(h); return 0;
    case WM_DESTROY: g_dashboardWindow = nullptr; EnableWindow(g_main, TRUE); SetForegroundWindow(g_main); return 0;
    }
    return DefWindowProcW(h, msg, wp, lp);
}
void showDashboard() {
    if (g_dashboardWindow) { SetForegroundWindow(g_dashboardWindow); return; }
    WNDCLASSEXW wc{sizeof(wc)}; wc.lpfnWndProc = DashboardProc;
    wc.hInstance = GetModuleHandleW(nullptr); wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = g_bgBrush; wc.lpszClassName = L"StringRipperDashboard";
    RegisterClassExW(&wc);
    RECT r{0, 0, S(600), S(505)};
    AdjustWindowRectEx(&r, WS_CAPTION | WS_SYSMENU, FALSE, WS_EX_DLGMODALFRAME);
    EnableWindow(g_main, FALSE);
    g_dashboardWindow = CreateWindowExW(WS_EX_DLGMODALFRAME, wc.lpszClassName, L"Results dashboard",
        WS_CAPTION | WS_SYSMENU, CW_USEDEFAULT, CW_USEDEFAULT, r.right-r.left, r.bottom-r.top,
        g_main, nullptr, wc.hInstance, nullptr);
    if (!g_dashboardWindow) { EnableWindow(g_main, TRUE); return; }
    ShowWindow(g_dashboardWindow, SW_SHOW); UpdateWindow(g_dashboardWindow);
}

enum : int { SS_INCLUDE = 6200, SS_EXCLUDE, SS_MIN, SS_MAX, SS_AFTER, SS_BEFORE,
             SS_START, SS_END, SS_APPLY, SS_CANCEL };
HWND g_ss = nullptr, g_ssInclude, g_ssExclude, g_ssMin, g_ssMax, g_ssAfter, g_ssBefore,
     g_ssStart, g_ssEnd;
std::wstring dateString(int64_t stamp) {
    if (!stamp) return {};
    std::time_t t = static_cast<std::time_t>(stamp);
    std::tm tm{}; localtime_s(&tm, &t);
    wchar_t buffer[20]{};
    wcsftime(buffer, 20, L"%Y-%m-%d", &tm);
    return buffer;
}
int64_t parseDate(HWND field, bool endOfDay) {
    auto text = narrow(controlText(field).c_str());
    if (text.empty()) return 0;
    std::tm date{}; std::istringstream input(text); input >> std::get_time(&date, "%Y-%m-%d");
    if (input.fail() || input.peek() != EOF) throw std::invalid_argument("Dates must use YYYY-MM-DD");
    date.tm_hour = endOfDay ? 23 : 0;
    date.tm_min = endOfDay ? 59 : 0;
    date.tm_sec = endOfDay ? 59 : 0;
    date.tm_isdst = -1;
    auto stamp = std::mktime(&date);
    if (stamp == -1) throw std::invalid_argument("Date is outside the supported range");
    return static_cast<int64_t>(stamp);
}
uint64_t parseSize(HWND field) {
    auto text = narrow(controlText(field).c_str());
    if (text.empty()) return 0;
    std::size_t used = 0;
    auto value = std::stoull(text, &used, 0);
    if (used != text.size()) throw std::invalid_argument("Sizes and ranges must be whole numbers (decimal or 0x hex)");
    return value;
}
LRESULT CALLBACK ScanSettingsProc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        darkTitle(h);
        peCtl(h, L"STATIC", L"File selection and scan range", 0, 0, 20, 14, 540, 25);
        auto row = [&](const wchar_t* label, int id, int y, HWND& field, const std::wstring& value) {
            peCtl(h, L"STATIC", label, 0, 0, 20, y + 4, 160, 22);
            field = peCtl(h, L"EDIT", value.c_str(), id, ES_AUTOHSCROLL | WS_BORDER,
                          185, y, 375, 27);
        };
        row(L"Include patterns", SS_INCLUDE, 50, g_ssInclude, widen(g_fileSelection.include));
        row(L"Exclude paths/patterns", SS_EXCLUDE, 88, g_ssExclude, widen(g_fileSelection.exclude));
        row(L"Minimum bytes", SS_MIN, 126, g_ssMin,
            g_fileSelection.minSize ? std::to_wstring(g_fileSelection.minSize) : L"");
        row(L"Maximum bytes", SS_MAX, 164, g_ssMax,
            g_fileSelection.maxSize ? std::to_wstring(g_fileSelection.maxSize) : L"");
        row(L"Modified after", SS_AFTER, 202, g_ssAfter, dateString(g_fileSelection.modifiedAfter));
        row(L"Modified before", SS_BEFORE, 240, g_ssBefore, dateString(g_fileSelection.modifiedBefore));
        row(L"Range start", SS_START, 278, g_ssStart,
            g_fileSelection.rangeStart ? std::to_wstring(g_fileSelection.rangeStart) : L"");
        row(L"Range end (exclusive)", SS_END, 316, g_ssEnd,
            g_fileSelection.rangeEnd ? std::to_wstring(g_fileSelection.rangeEnd) : L"");
        peCtl(h, L"STATIC", L"Patterns: *.txt, *.log. Separate with commas. Empty size/date/range = no limit.",
              0, 0, 20, 355, 540, 30);
        peCtl(h, L"BUTTON", L"Apply", SS_APPLY, BS_DEFPUSHBUTTON, 344, 400, 102, 30);
        peCtl(h, L"BUTTON", L"Cancel", SS_CANCEL, BS_PUSHBUTTON, 456, 400, 104, 30);
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == SS_CANCEL || LOWORD(wp) == IDCANCEL) { DestroyWindow(h); return 0; }
        if (LOWORD(wp) == SS_APPLY) {
            try {
                ur::FileSelection selection;
                selection.include = narrow(controlText(g_ssInclude).c_str());
                selection.exclude = narrow(controlText(g_ssExclude).c_str());
                selection.minSize = parseSize(g_ssMin); selection.maxSize = parseSize(g_ssMax);
                selection.modifiedAfter = parseDate(g_ssAfter, false);
                selection.modifiedBefore = parseDate(g_ssBefore, true);
                selection.rangeStart = parseSize(g_ssStart); selection.rangeEnd = parseSize(g_ssEnd);
                if (selection.maxSize && selection.maxSize < selection.minSize)
                    throw std::invalid_argument("Maximum size must be at least minimum size");
                if (selection.rangeEnd && selection.rangeEnd <= selection.rangeStart)
                    throw std::invalid_argument("Range end must be greater than start");
                if (selection.modifiedAfter && selection.modifiedBefore &&
                    selection.modifiedBefore < selection.modifiedAfter)
                    throw std::invalid_argument("Modified-before date must not precede modified-after date");
                g_fileSelection = std::move(selection);
                SetWindowTextW(g_status, L"Scan settings applied");
                DestroyWindow(h);
            } catch (const std::exception& e) {
                MessageBoxW(h, widen(e.what()).c_str(), L"Invalid scan settings", MB_ICONWARNING);
            }
            return 0;
        }
        break;
    case WM_CTLCOLORSTATIC: case WM_CTLCOLORBTN: {
        HDC dc = (HDC)wp; SetTextColor(dc, kText); SetBkColor(dc, kBg); return (LRESULT)g_bgBrush;
    }
    case WM_CTLCOLOREDIT: {
        HDC dc = (HDC)wp; SetTextColor(dc, kText); SetBkColor(dc, kBg2); return (LRESULT)g_bg2Brush;
    }
    case WM_ERASEBKGND: { RECT r; GetClientRect(h, &r); FillRect((HDC)wp, &r, g_bgBrush); return 1; }
    case WM_CLOSE: DestroyWindow(h); return 0;
    case WM_DESTROY: g_ss = nullptr; EnableWindow(g_main, TRUE); SetForegroundWindow(g_main); return 0;
    }
    return DefWindowProcW(h, msg, wp, lp);
}
void showScanSettings() {
    if (g_ss) { SetForegroundWindow(g_ss); return; }
    WNDCLASSEXW wc{sizeof(wc)}; wc.lpfnWndProc = ScanSettingsProc;
    wc.hInstance = GetModuleHandleW(nullptr); wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = g_bgBrush; wc.lpszClassName = L"StringRipperScanSettings";
    RegisterClassExW(&wc);
    RECT r{0, 0, S(580), S(445)};
    AdjustWindowRectEx(&r, WS_CAPTION | WS_SYSMENU, FALSE, WS_EX_DLGMODALFRAME);
    EnableWindow(g_main, FALSE);
    g_ss = CreateWindowExW(WS_EX_DLGMODALFRAME, wc.lpszClassName, L"Scan settings",
        WS_CAPTION | WS_SYSMENU, CW_USEDEFAULT, CW_USEDEFAULT, r.right-r.left, r.bottom-r.top,
        g_main, nullptr, wc.hInstance, nullptr);
    if (!g_ss) { EnableWindow(g_main, TRUE); return; }
    ShowWindow(g_ss, SW_SHOW); UpdateWindow(g_ss);
}

const ur::Finding* findingAtRow(int row) {
    if (row < 0 || row >= (int)g_rows.size() || g_rows[row].item < 0) return nullptr;
    return &g_viewResults[g_rows[row].group].items[g_rows[row].item];
}
/* what a row says: the value for a hit, the group name for a header */
std::wstring rowText(int row, int col) {
    if (row < 0 || row >= (int)g_rows.size()) return {};
    const auto& g = g_viewResults[g_rows[row].group];
    if (g_rows[row].item < 0) return col == 0 ? widen(g.name) : std::wstring();
    const auto& f = g.items[g_rows[row].item];
    switch (col) {
    case 0: return widen(f.value);
    case 1: return widen(ur::encName(f.enc));
    case 2: return widen(f.source);
    default: {
        if (!f.hasOffset) return {};
        wchar_t a[32]; _snwprintf_s(a, _TRUNCATE, L"0x%llX", (unsigned long long)f.offset);
        return a;
    }
    }
}
/* a header row: name, count chip, Copy all pill; false when the pill does not fit */
bool headerParts(HWND lv, HDC dc, int row, RECT& chip, RECT& pill) {
    RECT rr{}; ListView_GetItemRect(lv, row, &rr, LVIR_BOUNDS);
    const auto& g = g_viewResults[g_rows[row].group];
    HFONT of = (HFONT)SelectObject(dc, g_fontMono);
    std::wstring t = widen(g.name), cnt = std::to_wstring(g.items.size());
    SIZE sz{}; GetTextExtentPoint32W(dc, t.c_str(), (int)t.size(), &sz);
    SelectObject(dc, g_font);
    SIZE cs{}, ps{}; GetTextExtentPoint32W(dc, cnt.c_str(), (int)cnt.size(), &cs);
    GetTextExtentPoint32W(dc, L"Copy all", 8, &ps);
    SelectObject(dc, of);
    const int ch = S(18), top = (rr.top + rr.bottom - ch) / 2;
    chip = { rr.left + S(12) + sz.cx + S(10), top, 0, top + ch };
    chip.right = chip.left + cs.cx + S(14);
    pill = { chip.right + S(6), top, chip.right + S(6) + ps.cx + S(18), top + ch };
    return pill.right < rr.right - S(8);
}
void drawResultRow(HWND lv, HDC dc, int row) {
    if (row < 0 || row >= (int)g_rows.size()) return;
    static HBRUSH selBrush = CreateSolidBrush(kSel), cardBrush = CreateSolidBrush(kCard);
    RECT rr{}; ListView_GetItemRect(lv, row, &rr, LVIR_BOUNDS);
    const bool sel = (ListView_GetItemState(lv, row, LVIS_SELECTED) & LVIS_SELECTED) != 0;
    const auto& g = g_viewResults[g_rows[row].group];
    SetBkMode(dc, TRANSPARENT);
    HFONT of = (HFONT)SelectObject(dc, g_fontMono);
    if (g_rows[row].item < 0) {
        FillRect(dc, &rr, sel ? selBrush : g_bgBrush);
        HPEN pen = CreatePen(PS_SOLID, 1, kBSub), op = (HPEN)SelectObject(dc, pen);
        MoveToEx(dc, rr.left, rr.bottom - 1, nullptr); LineTo(dc, rr.right, rr.bottom - 1);
        SelectObject(dc, op); DeleteObject(pen);
        std::wstring t = widen(g.name);
        RECT tr = rr; tr.left += S(12);
        SIZE sz{}; GetTextExtentPoint32W(dc, t.c_str(), (int)t.size(), &sz);
        SetTextColor(dc, kText);
        DrawTextW(dc, t.c_str(), -1, &tr, DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);
        std::wstring cnt = std::to_wstring(g.items.size());
        SelectObject(dc, g_font);
        const int ch = S(18);
        RECT chip, pill;
        const bool fits = headerParts(lv, dc, row, chip, pill);
        if (chip.right < rr.right - S(8)) {
            roundRect(dc, chip, ch, kBg, kBDef);
            inkText(dc, cnt.c_str(), chip, g_font, kText2, DT_SINGLELINE | DT_CENTER | DT_VCENTER);
        }
        if (fits) {
            const bool hot = g_pillHot == row;
            roundRect(dc, pill, ch, hot ? kBg3 : kBg2, hot ? kBDef : kBSub);
            inkText(dc, L"Copy all", pill, g_font, hot ? kText : kText2, DT_SINGLELINE | DT_CENTER | DT_VCENTER);
        }
        SelectObject(dc, of);
        return;
    }
    FillRect(dc, &rr, sel ? selBrush : cardBrush);
    const auto& f = g.items[g_rows[row].item];
    int x = rr.left;
    for (int c = 0; c < 4; ++c) {
        const int w = ListView_GetColumnWidth(lv, c);
        RECT cr{ x + S(6), rr.top, x + w - S(6), rr.bottom };
        x += w;
        std::wstring t = rowText(row, c);
        if (c == 1) {
            SelectObject(dc, g_font);
            SIZE sz{}; GetTextExtentPoint32W(dc, t.c_str(), (int)t.size(), &sz);
            const int ch = S(20);
            RECT chip{ cr.left, (rr.top + rr.bottom - ch) / 2, cr.left + sz.cx + S(14), (rr.top + rr.bottom - ch) / 2 + ch };
            roundRect(dc, chip, S(12), kBg3, kBg3);
            inkText(dc, t.c_str(), chip, g_font, kText2, DT_SINGLELINE | DT_CENTER | DT_VCENTER);
            SelectObject(dc, g_fontMono);
            continue;
        }
        if (c == 0 && f.occurrences > 1) {
            std::wstring times = L"\u00D7" + std::to_wstring(f.occurrences);
            SelectObject(dc, g_font);
            SIZE sz{}; GetTextExtentPoint32W(dc, times.c_str(), (int)times.size(), &sz);
            const int ch = S(18);
            RECT chip{ cr.right - sz.cx - S(12), (rr.top + rr.bottom - ch) / 2, cr.right, (rr.top + rr.bottom - ch) / 2 + ch };
            roundRect(dc, chip, ch, kBg, kBDef);
            inkText(dc, times.c_str(), chip, g_font, kText2, DT_SINGLELINE | DT_CENTER | DT_VCENTER);
            SelectObject(dc, g_fontMono);
            cr.right = chip.left - S(6);
        }
        SetTextColor(dc, c == 2 ? kText3 : kText);
        DrawTextW(dc, t.c_str(), -1, &cr, DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);
    }
    SelectObject(dc, of);
}

/* the header row whose Copy all pill is under pt (list client coords), or -1 */
int pillAt(POINT pt) {
    LVHITTESTINFO hi{}; hi.pt = pt;
    const int row = ListView_HitTest(g_results, &hi);
    if (row < 0 || row >= (int)g_rows.size() || g_rows[row].item >= 0) return -1;
    HDC dc = GetDC(g_results);
    RECT chip, pill;
    const bool fits = headerParts(g_results, dc, row, chip, pill);
    ReleaseDC(g_results, dc);
    return fits && PtInRect(&pill, pt) ? row : -1;
}

/* drag a row out: the value, or the group name from a header row */
struct DropSource final : IDropSource {
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID id, void** out) override {
        if (id == IID_IUnknown || id == IID_IDropSource) { *out = this; return S_OK; }
        *out = nullptr; return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return 1; }
    ULONG STDMETHODCALLTYPE Release() override { return 1; }
    HRESULT STDMETHODCALLTYPE QueryContinueDrag(BOOL esc, DWORD keys) override {
        if (esc) return DRAGDROP_S_CANCEL;
        return (keys & MK_LBUTTON) ? S_OK : DRAGDROP_S_DROP;
    }
    HRESULT STDMETHODCALLTYPE GiveFeedback(DWORD) override { return DRAGDROP_S_USEDEFAULTCURSORS; }
};
void dragText(const std::wstring& text) {
    if (text.empty()) return;
    IDataObject* data = nullptr;
    if (FAILED(SHCreateDataObject(nullptr, 0, nullptr, nullptr, IID_PPV_ARGS(&data)))) return;
    FORMATETC fe{ CF_UNICODETEXT, nullptr, DVASPECT_CONTENT, -1, TYMED_HGLOBAL };
    STGMEDIUM sm{}; sm.tymed = TYMED_HGLOBAL;
    sm.hGlobal = GlobalAlloc(GMEM_MOVEABLE, (text.size() + 1) * sizeof(wchar_t));
    if (sm.hGlobal) {
        memcpy(GlobalLock(sm.hGlobal), text.c_str(), (text.size() + 1) * sizeof(wchar_t));
        GlobalUnlock(sm.hGlobal);
        if (SUCCEEDED(data->SetData(&fe, &sm, TRUE))) {
            DropSource src; DWORD effect = 0;
            DoDragDrop(data, &src, DROPEFFECT_COPY, &effect);
        } else GlobalFree(sm.hGlobal);
    }
    data->Release();
}
/* the filter field takes text from anywhere (first line), and files like the window does */
struct FilterDrop final : IDropTarget {
    DWORD effect = DROPEFFECT_NONE;
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID id, void** out) override {
        if (id == IID_IUnknown || id == IID_IDropTarget) { *out = this; return S_OK; }
        *out = nullptr; return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return 1; }
    ULONG STDMETHODCALLTYPE Release() override { return 1; }
    static bool has(IDataObject* d, CLIPFORMAT cf) {
        FORMATETC fe{ cf, nullptr, DVASPECT_CONTENT, -1, TYMED_HGLOBAL };
        return d && d->QueryGetData(&fe) == S_OK;
    }
    HRESULT STDMETHODCALLTYPE DragEnter(IDataObject* d, DWORD, POINTL, DWORD* e) override {
        effect = has(d, CF_UNICODETEXT) || has(d, CF_HDROP) ? DROPEFFECT_COPY : DROPEFFECT_NONE;
        *e = effect; return S_OK;
    }
    HRESULT STDMETHODCALLTYPE DragOver(DWORD, POINTL, DWORD* e) override { *e = effect; return S_OK; }
    HRESULT STDMETHODCALLTYPE DragLeave() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE Drop(IDataObject* d, DWORD, POINTL, DWORD* e) override {
        *e = DROPEFFECT_NONE;
        STGMEDIUM sm{};
        FORMATETC text{ CF_UNICODETEXT, nullptr, DVASPECT_CONTENT, -1, TYMED_HGLOBAL };
        FORMATETC files{ CF_HDROP, nullptr, DVASPECT_CONTENT, -1, TYMED_HGLOBAL };
        if (d->GetData(&text, &sm) == S_OK) {
            const auto* w = (const wchar_t*)GlobalLock(sm.hGlobal);
            const SIZE_T cap = GlobalSize(sm.hGlobal) / sizeof(wchar_t);
            std::wstring t = w ? std::wstring(w, wcsnlen(w, cap)) : std::wstring();
            GlobalUnlock(sm.hGlobal); ReleaseStgMedium(&sm);
            t = t.substr(0, t.find_first_of(L"\r\n"));
            if (t.size() > 255) t.resize(255);
            SetWindowTextW(g_filter, t.c_str());
            SetFocus(g_filter);
            *e = DROPEFFECT_COPY;
        } else if (d->GetData(&files, &sm) == S_OK) {
            std::vector<std::filesystem::path> paths;
            auto drop = (HDROP)GlobalLock(sm.hGlobal);
            UINT n = drop ? DragQueryFileW(drop, 0xFFFFFFFF, nullptr, 0) : 0;
            for (UINT i = 0; i < n; ++i) {
                std::wstring f(DragQueryFileW(drop, i, nullptr, 0) + 1, L'\0');
                f.resize(DragQueryFileW(drop, i, f.data(), (UINT)f.size()));
                paths.push_back(std::move(f));
            }
            GlobalUnlock(sm.hGlobal); ReleaseStgMedium(&sm);
            if (!paths.empty()) { setSourcePaths(std::move(paths)); SetWindowTextW(g_status, L"Dropped. Hit Scan."); }
            *e = DROPEFFECT_COPY;
        }
        return S_OK;
    }
} g_filterDrop;
void showFindingDetails(ur::Finding f) {
    std::wstring s = L"Value: " + widen(f.value) + L"\r\nGroup: " + widen(f.group) +
        L"\r\nEncoding: " + widen(ur::encName(f.enc)) + L"\r\nSource: " + widen(f.source);
    if (f.hasOffset) {
        wchar_t at[40]; _snwprintf_s(at, _TRUNCATE, L"\r\nOffset/address: 0x%llX", (unsigned long long)f.offset);
        s += at;
    }
    if (!f.before.empty() || !f.after.empty())
        s += L"\r\n\r\nContext:\r\n" + widen(f.before) + L"[" + widen(f.value) + L"]" + widen(f.after);
    if (!f.captures.empty()) {
        s += L"\r\n\r\nNamed captures:";
        for (const auto& [name, value] : f.captures)
            s += L"\r\n" + widen(name) + L": " + widen(value);
    }
    MessageBoxW(g_main, s.c_str(), L"Finding details", MB_OK | MB_ICONINFORMATION);
}
/* byte inspector: offsets, hex and ASCII in three panes that scroll together,
   so a selection in one pane copies (or drags) only that pane's text. Starts
   with 4 KiB around the hit and grows 4 KiB at a time in either direction. */
enum : int { IN_EARLIER = 6400, IN_LATER, IN_INFO };
struct Inspect { bool file = false; std::filesystem::path path; uint32_t pid = 0; uint64_t start = 0, hit = 0; std::vector<uint8_t> bytes; };
Inspect g_ins;
HWND g_inspector = nullptr, g_insPane[3]{}, g_insInfo = nullptr;
bool g_insSyncing = false;
constexpr std::size_t kInspectStep = 4096;

std::size_t inspectRead(uint64_t at, uint8_t* out, std::size_t n) {
    std::size_t got = 0;
    if (g_ins.file) {
        std::ifstream in(g_ins.path, std::ios::binary);
        if (in) { in.seekg((std::streamoff)at); in.read((char*)out, (std::streamsize)n); got = (std::size_t)std::max<std::streamsize>(0, in.gcount()); }
    } else if (g_ins.pid) {
        fxchain::RipStats stats; fxchain::RipTargetInfo info;
        fxchain::ripBackend().withReader(g_ins.pid, stats, info, [&](fxchain::IMemoryReader& r) { got = r.read(at, out, n).bytesRead; });
    }
    return got;
}
/* earlier bytes: one read, or line by line back to the first unreadable one */
std::size_t inspectEarlier() {
    const std::size_t want = (std::size_t)std::min<uint64_t>(kInspectStep, g_ins.start);
    if (!want) return 0;
    std::vector<uint8_t> buf(want);
    if (inspectRead(g_ins.start - want, buf.data(), want) != want) {
        buf.clear();
        for (std::size_t back = 16; back <= want; back += 16) {
            uint8_t line[16];
            if (inspectRead(g_ins.start - back, line, 16) != 16) break;
            buf.insert(buf.begin(), line, line + 16);
        }
    }
    g_ins.bytes.insert(g_ins.bytes.begin(), buf.begin(), buf.end());
    g_ins.start -= buf.size();
    return buf.size();
}
std::size_t inspectLater() {
    std::vector<uint8_t> buf(kInspectStep);
    const std::size_t got = inspectRead(g_ins.start + g_ins.bytes.size(), buf.data(), buf.size());
    g_ins.bytes.insert(g_ins.bytes.end(), buf.begin(), buf.begin() + got);
    return got;
}
void inspectMark(HWND pane, long from, long to) {
    CHARFORMAT2W cf{}; cf.cbSize = sizeof(cf);
    cf.dwMask = CFM_COLOR | CFM_BOLD | CFM_BACKCOLOR; cf.crTextColor = kText; cf.crBackColor = kAccent; cf.dwEffects = CFE_BOLD;
    SendMessageW(pane, EM_SETREADONLY, FALSE, 0);     // read-only rich edits ignore selection formats
    SendMessageW(pane, EM_SETSEL, from, to);
    SendMessageW(pane, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cf);
    SendMessageW(pane, EM_SETSEL, from, from);
    SendMessageW(pane, EM_SETREADONLY, TRUE, 0);
}
void inspectAlign(int top);
void inspectRender(int top) {
    std::wstring off, hex, asc;
    const std::size_t n = g_ins.bytes.size();
    int hitLine = -1;
    for (std::size_t i = 0; i < n; i += 16) {
        if (i) { off += L'\r'; hex += L'\r'; asc += L'\r'; }
        wchar_t a[24]; _snwprintf_s(a, _TRUNCATE, L"%012llX", (unsigned long long)(g_ins.start + i));
        off += a;
        if (g_ins.hit >= g_ins.start + i && g_ins.hit < g_ins.start + i + 16) hitLine = int(i / 16);
        for (std::size_t j = 0; j < 16 && i + j < n; ++j) {
            wchar_t b[4]; _snwprintf_s(b, _TRUNCATE, j ? L" %02X" : L"%02X", unsigned(g_ins.bytes[i + j]));
            hex += b;
            const uint8_t c = g_ins.bytes[i + j];
            asc += (c >= 32 && c <= 126) ? wchar_t(c) : L'.';
        }
    }
    const std::wstring* texts[3] = {&off, &hex, &asc};
    for (int k = 0; k < 3; ++k) {
        SetWindowTextW(g_insPane[k], texts[k]->c_str());
        CHARFORMAT2W cf{}; cf.cbSize = sizeof(cf); cf.dwMask = CFM_COLOR | CFM_BOLD | CFM_BACKCOLOR;
        cf.crTextColor = kText; cf.crBackColor = kBg2;
        SendMessageW(g_insPane[k], EM_SETCHARFORMAT, SCF_ALL, (LPARAM)&cf);
    }
    if (hitLine >= 0) {
        const long col = long(g_ins.hit - (g_ins.start + uint64_t(hitLine) * 16));
        /* every line before the hit is full: 12+1, 47+1 and 16+1 characters; EM_LINEINDEX
           is no help here, rich edit lays the new text out later and answers -1 */
        const long l0 = hitLine * 13L, l1 = hitLine * 48L, l2 = hitLine * 17L;
        inspectMark(g_insPane[0], l0, l0 + 12);
        inspectMark(g_insPane[1], l1 + col * 3, l1 + col * 3 + 2);
        inspectMark(g_insPane[2], l2 + col, l2 + col + 1);
    }
    inspectAlign(std::max(0, top));
    RedrawWindow(g_inspector ? g_inspector : GetParent(g_insPane[0]), nullptr, nullptr,
                 RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN | RDW_UPDATENOW);
    wchar_t info[160];
    _snwprintf_s(info, _TRUNCATE, L"0x%llX - 0x%llX   (%zu bytes)   hit at 0x%llX",
                 (unsigned long long)g_ins.start, (unsigned long long)(g_ins.start + n),
                 n, (unsigned long long)g_ins.hit);
    SetWindowTextW(g_insInfo, info);
}
/* all panes on one first line; panes clamp differently near the end, so the lowest wins */
void inspectAlign(int top) {
    g_insSyncing = true;
    for (int pass = 0; pass < 2; ++pass) {
        for (HWND o : g_insPane) if (o && IsWindow(o))
            SendMessageW(o, EM_LINESCROLL, 0, top - (int)SendMessageW(o, EM_GETFIRSTVISIBLELINE, 0, 0));
        for (HWND o : g_insPane) if (o && IsWindow(o)) top = std::min(top, (int)SendMessageW(o, EM_GETFIRSTVISIBLELINE, 0, 0));
    }
    g_insSyncing = false;
}
LRESULT CALLBACK insPaneSub(HWND h, UINT msg, WPARAM wp, LPARAM lp, UINT_PTR, DWORD_PTR) {
    if (msg == WM_MOUSEWHEEL) {     /* scroll by lines here: RichEdit hands wheels to the window under the cursor */
        UINT step = 3; SystemParametersInfoW(SPI_GETWHEELSCROLLLINES, 0, &step, 0);
        if (step == WHEEL_PAGESCROLL || step == 0) step = 3;
        const int lines = -GET_WHEEL_DELTA_WPARAM(wp) * int(step) / WHEEL_DELTA;
        inspectAlign(std::max(0, (int)SendMessageW(h, EM_GETFIRSTVISIBLELINE, 0, 0) + lines));
        return 0;
    }
    if (msg == WM_NCDESTROY) RemoveWindowSubclass(h, insPaneSub, 0);
    LRESULT r = DefSubclassProc(h, msg, wp, lp);
    const bool scrolls = msg == WM_VSCROLL || msg == WM_KEYDOWN || msg == WM_LBUTTONUP || msg == WM_TIMER ||
                         (msg == WM_MOUSEMOVE && (wp & MK_LBUTTON));
    if (scrolls && !g_insSyncing && g_inspector) inspectAlign((int)SendMessageW(h, EM_GETFIRSTVISIBLELINE, 0, 0));
    return r;
}
LRESULT CALLBACK InspectorProc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        darkTitle(h);
        HDC dc = GetDC(h); HFONT of = (HFONT)SelectObject(dc, g_fontMono);
        SIZE ch{}; GetTextExtentPoint32W(dc, L"0", 1, &ch);
        SelectObject(dc, of); ReleaseDC(h, dc);
        const int x0 = S(14), y0 = S(44), hgt = S(470), pad = S(10);
        const int w[3] = { ch.cx * 13 + pad, ch.cx * 48 + pad, ch.cx * 17 + pad + GetSystemMetrics(SM_CXVSCROLL) };
        g_insInfo = peCtl(h, L"STATIC", L"", IN_INFO, 0, 14, 12, 760, 24);
        int x = x0;
        for (int k = 0; k < 3; ++k) {
            g_insPane[k] = CreateWindowExW(0, MSFTEDIT_CLASS, L"",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_MULTILINE | ES_READONLY | (k == 2 ? WS_VSCROLL : 0),
                x, y0, w[k], hgt, h, nullptr, nullptr, nullptr);
            SendMessageW(g_insPane[k], WM_SETFONT, (WPARAM)g_fontMono, TRUE);
            SendMessageW(g_insPane[k], EM_SETBKGNDCOLOR, 0, (LPARAM)kBg2);
            SendMessageW(g_insPane[k], EM_SETTARGETDEVICE, 0, 1);      // no word wrap: one line is 16 bytes
            SendMessageW(g_insPane[k], EM_EXLIMITTEXT, 0, -1);          // more than the 32k default once grown
            RECT pr{ pad / 2, S(4), w[k] - (k == 2 ? GetSystemMetrics(SM_CXVSCROLL) : 0) - pad / 2, hgt - S(4) };
            SendMessageW(g_insPane[k], EM_SETRECT, 0, (LPARAM)&pr);
            SetWindowSubclass(g_insPane[k], insPaneSub, 0, 0);
            x += w[k] + S(6);
        }
        RECT cr; GetClientRect(h, &cr);
        const int by = y0 + hgt + S(12);
        CreateWindowExW(0, L"BUTTON", L"Load earlier 4 KiB", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                        x0, by, S(170), S(30), h, (HMENU)(INT_PTR)IN_EARLIER, nullptr, nullptr);
        CreateWindowExW(0, L"BUTTON", L"Load later 4 KiB", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                        x0 + S(180), by, S(170), S(30), h, (HMENU)(INT_PTR)IN_LATER, nullptr, nullptr);
        CreateWindowExW(0, L"BUTTON", L"Close", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                        cr.right - x0 - S(110), by, S(110), S(30), h, (HMENU)(INT_PTR)IDCANCEL, nullptr, nullptr);
        for (HWND c = GetWindow(h, GW_CHILD); c; c = GetWindow(c, GW_HWNDNEXT))
            if (c != g_insPane[0] && c != g_insPane[1] && c != g_insPane[2]) {
                SendMessageW(c, WM_SETFONT, (WPARAM)g_font, TRUE);
                SetWindowTheme(c, L"DarkMode_Explorer", nullptr);
            }
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == IDCANCEL) { DestroyWindow(h); return 0; }
        if (LOWORD(wp) == IN_EARLIER || LOWORD(wp) == IN_LATER) {
            const int top = (int)SendMessageW(g_insPane[2], EM_GETFIRSTVISIBLELINE, 0, 0);
            if (LOWORD(wp) == IN_EARLIER) {
                const std::size_t got = inspectEarlier();
                if (!got) { SetWindowTextW(g_insInfo, L"Nothing readable before this."); return 0; }
                inspectRender(top + int(got / 16));
            } else {
                if (!inspectLater()) { SetWindowTextW(g_insInfo, L"Nothing readable after this."); return 0; }
                inspectRender(top);
            }
            return 0;
        }
        break;
    case WM_CTLCOLORSTATIC: case WM_CTLCOLORBTN: {
        HDC dc = (HDC)wp; SetTextColor(dc, kText); SetBkColor(dc, kBg); return (LRESULT)g_bgBrush;
    }
    case WM_ERASEBKGND: { RECT r; GetClientRect(h, &r); FillRect((HDC)wp, &r, g_bgBrush); return 1; }
    case WM_CLOSE: DestroyWindow(h); return 0;
    case WM_DESTROY:
        g_inspector = nullptr; for (HWND& p : g_insPane) p = nullptr;
        EnableWindow(g_main, TRUE); SetForegroundWindow(g_main); return 0;
    }
    return DefWindowProcW(h, msg, wp, lp);
}
void showOffsetInspector() {
    WNDCLASSEXW wc{sizeof(wc)}; wc.lpfnWndProc = InspectorProc;
    wc.hInstance = GetModuleHandleW(nullptr); wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = g_bgBrush; wc.lpszClassName = L"StringRipperOffsetInspector";
    RegisterClassExW(&wc);
    HDC dc = GetDC(g_main); HFONT of = (HFONT)SelectObject(dc, g_fontMono);
    SIZE ch{}; GetTextExtentPoint32W(dc, L"0", 1, &ch);
    SelectObject(dc, of); ReleaseDC(g_main, dc);
    const int width = S(14) * 2 + ch.cx * (13 + 48 + 17) + S(10) * 3 + GetSystemMetrics(SM_CXVSCROLL) + S(12);
    RECT r{0, 0, std::max<int>(width, S(640)), S(570)};
    AdjustWindowRectEx(&r, WS_CAPTION | WS_SYSMENU, FALSE, WS_EX_DLGMODALFRAME);
    EnableWindow(g_main, FALSE);
    g_inspector = CreateWindowExW(WS_EX_DLGMODALFRAME, wc.lpszClassName, L"Offset inspector",
        WS_CAPTION | WS_SYSMENU, CW_USEDEFAULT, CW_USEDEFAULT, r.right-r.left, r.bottom-r.top,
        g_main, nullptr, wc.hInstance, nullptr);
    if (!g_inspector) { EnableWindow(g_main, TRUE); return; }
    ShowWindow(g_inspector, SW_SHOW); UpdateWindow(g_inspector);
    inspectRender(int((g_ins.hit - g_ins.start) / 16) - 8);     /* after showing: marks set during WM_CREATE do not stick */
}
/* a process finding's pid: "(pid N)" in its source when several were scanned,
   and only while that process is still part of the shown results */
uint32_t findingPid(const ur::Finding& f) {
    auto at = f.source.find(" (pid ");
    if (at == std::string::npos) return g_resultsPid;
    const auto pid = uint32_t(std::strtoul(f.source.c_str() + at + 6, nullptr, 10));
    return std::find(g_resultsPids.begin(), g_resultsPids.end(), pid) != g_resultsPids.end() ? pid : 0;
}

void inspectOffset(const ur::Finding& f, bool file) {
    if (!f.hasOffset || g_inspector) return;
    g_ins = Inspect{};
    g_ins.file = file;
    if (file) { const auto path = ur::pathFromUtf8(f.source); if (path) g_ins.path = *path; }
    else g_ins.pid = findingPid(f);
    g_ins.hit = f.offset;
    g_ins.start = (f.offset > kInspectStep / 2 ? f.offset - kInspectStep / 2 : 0) & ~uint64_t(15);
    std::vector<uint8_t> buf(kInspectStep);
    std::size_t got = inspectRead(g_ins.start, buf.data(), buf.size());
    if (!got || g_ins.start + got <= f.offset) {
        g_ins.start = f.offset & ~uint64_t(15);
        got = inspectRead(g_ins.start, buf.data(), buf.size());
    }
    if (!got) {
        MessageBoxW(g_main, L"Source bytes are no longer readable.", L"Offset inspector", MB_ICONWARNING);
        return;
    }
    buf.resize(got);
    g_ins.bytes = std::move(buf);
    showOffsetInspector();
}
void showFindingMenu(ur::Finding f) {
    HMENU menu = CreatePopupMenu();
    AppendMenuW(menu, MF_STRING, 1, L"Details and context");
    std::error_code ec;
    const auto path = ur::pathFromUtf8(f.source);
    bool file = path && std::filesystem::is_regular_file(*path, ec);
    const uint32_t pid = file ? 0 : findingPid(f);
    const std::string process = pid ? fxchain::ripBackend().processName(pid) : std::string{};
    if (file) AppendMenuW(menu, MF_STRING, 2, L"Open source file");
    if (f.hasOffset && (file || pid)) AppendMenuW(menu, MF_STRING, 4, L"Inspect bytes at offset");
    AppendMenuW(menu, MF_STRING, 3, process.empty() ? L"Favorite source" : L"Favorite process");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    if (g_lastMode == ur::Mode::Urls) AppendMenuW(menu, MF_STRING, 5, (L"Ignore " + widen(f.group)).c_str());
    AppendMenuW(menu, MF_STRING, 6, L"Ignore this value");
    AppendMenuW(menu, MF_STRING, 7, L"Edit ignore list...");
    POINT p; GetCursorPos(&p);
    int chosen = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, p.x, p.y, 0, g_main, nullptr);
    DestroyMenu(menu);
    if (chosen == 1) showFindingDetails(f);
    else if (chosen == 2 && file) ShellExecuteW(g_main, L"open", path->c_str(), nullptr, nullptr, SW_SHOWNORMAL);
    else if (chosen == 4) inspectOffset(f, file);
    else if (chosen == 3) {
        try { ur::SessionStore db(workspaceDatabase());
              if (!process.empty()) db.setFavorite("process", process, true);
              else db.setFavorite("source", f.source, true);
              SetWindowTextW(g_status, process.empty() ? L"Source added to favorites" : L"Process added to favorites"); }
        catch (const std::exception& e) { MessageBoxW(g_main, widen(e.what()).c_str(), L"Favorite", MB_ICONERROR); }
    }
    else if (chosen == 5 || chosen == 6) {
        const std::string rule = chosen == 5 ? f.group : "=" + f.value;
        if (std::find(g_ignoreLines.begin(), g_ignoreLines.end(), rule) == g_ignoreLines.end()) g_ignoreLines.push_back(rule);
        setChecked(g_ignoreChip, true);
        saveIgnoreRules();
    }
    else if (chosen == 7) showIgnoreEditor();
}

bool putClipboard(const std::string& text) {
    if (text.empty() || !OpenClipboard(g_main)) return false;
    EmptyClipboard();
    std::wstring w = widen(text);
    HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, (w.size() + 1) * sizeof(wchar_t));
    bool ok = false;
    if (void* mem = h ? GlobalLock(h) : nullptr) {
        memcpy(mem, w.c_str(), (w.size() + 1) * sizeof(wchar_t));
        GlobalUnlock(h);
        ok = SetClipboardData(CF_UNICODETEXT, h) != nullptr;
    }
    if (h && !ok) GlobalFree(h);
    CloseClipboard();
    return ok;
}
/* every value the list shows in one group, once each, in list order */
void copyGroup(int group) {
    if (group < 0 || group >= (int)g_viewResults.size()) return;
    const auto& g = g_viewResults[group];
    std::string text;
    for (const auto& f : g.items) { text += f.value; text += "\r\n"; }
    if (putClipboard(text))
        SetWindowTextW(g_status, (L"Copied " + std::to_wstring(g.items.size()) + L" values of " + widen(g.name)).c_str());
}
void copySelected() {
    std::string text;
    int i = -1;
    while ((i = ListView_GetNextItem(g_results, i, LVNI_SELECTED)) != -1) {
        const auto* f = findingAtRow(i);
        if (!f) continue;
        text += f->value;
        text += "\r\n";
    }
    putClipboard(text);
}

void saveAsTxt() {
    if (g_viewResults.empty()) return;
    wchar_t buf[4096] = L"stringripper-results";
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_main;
    ofn.lpstrFile = buf;
    ofn.nMaxFile = 4096;
    ofn.lpstrFilter = L"Text file\0*.txt\0CSV file\0*.csv\0JSON file\0*.json\0SQLite database\0*.sqlite\0";
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_EXPLORER;
    if (::GetSaveFileNameW(&ofn)) {
        std::string format = ofn.nFilterIndex == 2 ? "csv" : ofn.nFilterIndex == 3 ? "json" :
                             ofn.nFilterIndex == 4 ? "sqlite" : "txt";
        std::filesystem::path path(buf);
        if (path.extension().empty()) {
            path += L"." + widen(format);
        }
        if (format == "sqlite") {
            try {
                ur::SessionStore db(path);
                auto id = db.saveSession({0, "Filtered export", "GUI results", "", g_viewHits});
                SetWindowTextW(g_status, (L"Saved SQLite session " + std::to_wstring(id)).c_str());
            } catch (const std::exception& e) {
                MessageBoxW(g_main, widen(e.what()).c_str(), L"SQLite export failed", MB_ICONERROR);
            }
            return;
        }
        std::error_code ec;
        if (std::filesystem::exists(path, ec) &&
            MessageBoxW(g_main, L"Replace the existing export file?", L"Export results",
                        MB_YESNO | MB_ICONQUESTION) != IDYES) return;
        if (!writeTextFile(path.wstring(), format == "txt" ? ur::plainList(g_viewResults) : ur::exportResults(g_viewHits, format)))
            MessageBoxW(g_main, L"Could not write the file.", L"StringRipper", MB_ICONERROR);
    }
}

void sendToEditor() {
    if (g_viewResults.empty()) return;
    wchar_t tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    std::wstring p = std::wstring(tmp) + L"StringRipper-" + std::to_wstring(GetTickCount64()) + L".txt";
    if (!writeTextFile(p, ur::plainList(g_viewResults))) {
        MessageBoxW(g_main, L"Could not write the temp file.", L"StringRipper", MB_ICONERROR);
        return;
    }
    ::ShellExecuteW(g_main, L"open", p.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
}

void layout(int cw, int ch) {
    const int m = S(14), rh = S(26), gap = S(14), hh = S(16), lh = S(20), hg = S(6), sp = S(8);
    const bool regex = isChecked(g_modeRegex);
    const int right = cw - m;
    int y = m;

    auto flow = [&](std::initializer_list<HWND> hs, int x, int top, int pad) {
        for (HWND h : hs) { int w = textW(h, g_font) + pad; MoveWindow(h, x, top, w, rh, TRUE); x += w + sp; }
        return x;
    };

    // SOURCE
    MoveWindow(g_secSource, m, y, S(200), hh, TRUE); y += hh + hg;
    int rw = textW(g_refresh, g_font) + S(26), fw = textW(g_file, g_font) + S(26);
    int setW = textW(g_settingsButton, g_font) + S(26);
    int sw2 = cw - m * 2 - rw - fw - setW - sp * 3;
    g_fields[0] = { m, y, m + sw2, y + rh };
    MoveWindow(g_search, m + S(6), y + S(4), sw2 - S(12), rh - S(8), TRUE);
    MoveWindow(g_refresh, right - fw - setW - rw - sp * 2, y, rw, rh, TRUE);
    MoveWindow(g_file, right - fw - setW - sp, y, fw, rh, TRUE);
    MoveWindow(g_settingsButton, right - setW, y, setW, rh, TRUE);
    y += rh + S(5);
    int aiw = textW(g_allInst, g_font) + S(24), kw = textW(g_kill, g_font) + S(26), dmw = textW(g_dump, g_font) + S(26);
    MoveWindow(g_kill, right - kw, y, kw, rh, TRUE);
    MoveWindow(g_dump, right - kw - sp - dmw, y, dmw, rh, TRUE);
    MoveWindow(g_allInst, right - kw - sp - dmw - sp - aiw, y, aiw, rh, TRUE);
    MoveWindow(g_source, m + S(6), y + S(4), cw - m * 2 - S(12) - aiw - dmw - kw - sp * 3, S(360), TRUE);   // 360 = dropdown height
    { RECT cr2; GetWindowRect(g_source, &cr2); MapWindowPoints(nullptr, g_main, (POINT*)&cr2, 2);
      InflateRect(&cr2, S(6), S(4)); g_fields[1] = cr2; }
    y += rh + hg;
    MoveWindow(g_srcInfo, m, y, cw - m * 2, lh, TRUE);
    y += lh + gap;

    // WHAT TO FIND
    MoveWindow(g_secFind, m, y, S(200), hh, TRUE); y += hh + hg;
    int mw1 = textW(g_modeUrl, g_font) + S(34), mw2 = textW(g_modeRegex, g_font) + S(34);
    const int pad = S(3);
    MoveWindow(g_modeUrl, m + pad, y + pad, mw1, rh - pad * 2, TRUE);
    MoveWindow(g_modeRegex, m + pad * 2 + mw1, y + pad, mw2, rh - pad * 2, TRUE);
    g_segRect = { m, y, m + pad * 3 + mw1 + mw2, y + rh };
    y += rh + hg;
    const int dy = y;
    int cx = flow({g_crap}, m, dy, S(24));
    MoveWindow(g_urlHint, cx + sp, dy + S(3), right - cx - sp, lh, TRUE);
    int lw = textW(g_customLabel, g_font) + sp;
    MoveWindow(g_presetLabel, m, dy + S(4), lw, lh, TRUE);
    flow({g_pEmail, g_pIpv4, g_pIpv6, g_pGuid, g_pApi, g_pPath, g_pDl}, m + lw + sp, dy, S(24));
    const int cy = dy + rh + hg;
    MoveWindow(g_customLabel, m, cy + S(4), lw, lh, TRUE);
    g_fields[2] = { m + lw + sp, cy, right, cy + rh };
    int pw = textW(g_presets, g_font) + S(26), pkw = S(240);
    g_fields[2].right = right - pw - sp - pkw - sp;
    MoveWindow(g_presets, right - pw, cy, pw, rh, TRUE);
    MoveWindow(g_presetPick, right - pw - sp - pkw + S(6), cy + S(4), pkw - S(12), S(300), TRUE);
    { RECT pr; GetWindowRect(g_presetPick, &pr); MapWindowPoints(nullptr, g_main, (POINT*)&pr, 2);
      InflateRect(&pr, S(6), S(4)); g_fields[4] = pr; }
    MoveWindow(g_custom, m + lw + sp + S(6), cy + S(4),
               g_fields[2].right - m - lw - sp - S(12), rh - S(8), TRUE);
    y = regex ? (cy + rh + gap) : (dy + rh + gap);

    // DECODE
    MoveWindow(g_secDecode, m, y, S(200), hh, TRUE); y += hh + hg;
    flow({g_ascii, g_utf16, g_b64, g_hex, g_esc}, m, y, S(24));
    y += rh + gap;

    // scan bar
    int sx = flow({g_scan, g_pause, g_cancel, g_monitor}, m, y, S(34));
    MoveWindow(g_monitorInterval, sx + sp, y + S(3), S(45), rh - S(6), TRUE);
    sx += sp + S(45);
    MoveWindow(g_status, sx + sp, y + S(4), right - sx - sp, lh, TRUE);
    y += rh + gap;

    // RESULTS
    int sw = textW(g_secResults, g_fontHdr, S(2)) + sp;
    MoveWindow(g_secResults, m, y + S(6), sw, hh, TRUE);
    g_fields[3] = { m + sw + sp, y, right, y + rh };
    int nw = textW(g_newOnly, g_font) + S(26);
    int iw = textW(g_ignoreChip, g_font) + S(26);
    int ww = textW(g_workspace, g_font) + S(26);
    int dw = textW(g_dashboard, g_font) + S(26);
    MoveWindow(g_newOnly, right - nw, y, nw, rh, TRUE);
    MoveWindow(g_ignoreChip, right - nw - sp - iw, y, iw, rh, TRUE);
    MoveWindow(g_workspace, right - nw - sp - iw - sp - ww, y, ww, rh, TRUE);
    MoveWindow(g_dashboard, right - nw - sp - iw - sp - ww - sp - dw, y, dw, rh, TRUE);
    g_fields[3].right = right - nw - sp - iw - sp - ww - sp - dw - sp;
    MoveWindow(g_filter, m + sw + sp + S(6), y + S(4),
        g_fields[3].right - m - sw - sp - S(12), rh - S(8), TRUE);
    y += rh + hg;

    int bottom = ch - m - rh;
    int listH = (bottom - gap) - y;
    if (listH < S(60)) listH = S(60);
    g_listCard = { m, y, right, y + listH };
    MoveWindow(g_results, m + S(7), y + S(7), cw - m * 2 - S(14), listH - S(14), TRUE);
    fitColumns();

    const int left = flow({g_copy, g_save, g_editor, g_clear}, m, bottom, S(26));
    int aw = textW(g_about, g_font) + S(26);
    MoveWindow(g_about, right - aw, bottom, aw, rh, TRUE);
    g_load.rect = { right - aw - S(16) - S(250), bottom, right - aw - S(16), bottom + rh };
    if (g_load.rect.left < left + S(8)) g_load.rect = {};
    if (g_load.tip) {
        TTTOOLINFOW ti{sizeof(ti)}; ti.hwnd = g_main; ti.uId = 1; ti.rect = g_load.rect;
        SendMessageW(g_load.tip, TTM_NEWTOOLRECTW, 0, (LPARAM)&ti);
    }
    InvalidateRect(g_main, nullptr, FALSE);

}

void fitColumns() {
    RECT lc; GetClientRect(g_results, &lc);
    int encW = S(90), offW = S(115);
    int srcW = std::clamp(g_srcWant + S(20), S(220), std::max(S(220), int(lc.right) * 2 / 5));
    int valW = lc.right - encW - srcW - offW;
    if (valW < S(160)) valW = S(160);
    ListView_SetColumnWidth(g_results, 0, valW);
    ListView_SetColumnWidth(g_results, 1, encW);
    ListView_SetColumnWidth(g_results, 2, srcW);
    ListView_SetColumnWidth(g_results, 3, offW);
}

void applyFonts() {
    for (HWND h : {g_search, g_source, g_refresh, g_file, g_settingsButton, g_srcInfo, g_modeUrl, g_modeRegex, g_urlHint,
                   g_presetLabel, g_pEmail, g_pIpv4, g_pIpv6, g_pGuid, g_pApi, g_pPath, g_customLabel,
                   g_custom, g_ascii, g_utf16, g_b64, g_hex, g_scan, g_pause, g_cancel, g_monitor,
                   g_monitorInterval, g_status, g_filter,
                   g_results, g_copy, g_save, g_editor, g_clear, g_about, g_crap, g_pDl, g_presets, g_newOnly,
                   g_pagePrev, g_pageNext, g_pageLabel, g_workspace, g_dashboard})
        setFont(h, g_font);
    for (HWND h : {g_secSource, g_secFind, g_secDecode, g_secResults})
        setFont(h, g_fontHdr);
}

void relayout(HWND hwnd) {
    RECT rc; GetClientRect(hwnd, &rc);
    layout(rc.right, rc.bottom);
    /* RDW_ALLCHILDREN: owner-draw statics and buttons keep stale pixels at their
       new spot after a move unless the child itself is invalidated too. */
    RedrawWindow(hwnd, nullptr, nullptr, RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN);
}

/*--- auto-update ---*/
static const wchar_t* kUpdateManifestUrl =
    L"https://github.com/akustikrausch/StringRipper/releases/latest/download/latest.json";
static const wchar_t* kReleasesPageUrl =
    L"https://github.com/akustikrausch/StringRipper/releases/latest";
std::filesystem::path g_updateDownloadPath;
std::atomic_bool g_updateCancel{false};

static std::wstring updateUserAgent() { return L"StringRipper/" + widen(STRINGRIPPER_VERSION); }
static void postUpdateError(const std::wstring& m) {
    PostMessageW(g_main, WM_APP_UPDATE_DONE, 0, (LPARAM)_wcsdup(m.c_str()));
}
static void updateProgress(long long got, long long total, void*) {
    int pct = total > 0 ? (int)(got * 100 / total) : 0;
    PostMessageW(g_main, WM_APP_UPDATE_PROGRESS, (WPARAM)pct, 0);
}

// Worker: fetch latest.json, decide. Only PostMessages back to the UI thread.
void runUpdateCheck(bool manual) {
    std::string json, err;
    if (!ur::httpGet(kUpdateManifestUrl, json, &err, 1 << 20, updateUserAgent(), nullptr, nullptr, &g_updateCancel)) {
        if (manual) postUpdateError(widen(err.empty() ? "update check failed" : err));
        return;
    }
    ur::UpdateInfo info;
    if (!ur::parseManifest(json, info)) { if (manual) postUpdateError(L"malformed update manifest"); return; }

    const std::string cur = STRINGRIPPER_VERSION;
    if (!ur::isNewerVersion(info.version, cur)) {
        if (manual) PostMessageW(g_main, WM_APP_UPDATE_UPTODATE, 0, 0);
        return;
    }
    // minVersion gate: too old to jump straight to the new build.
    if (!info.minVersion.empty() && info.minVersion != cur && ur::isNewerVersion(info.minVersion, cur)) {
        if (manual) postUpdateError(L"a newer version exists but needs a manual reinstall");
        return;
    }
    // No usable installer entry -> manual download only (open the release page).
    bool hashOk = info.sha256.size() == 64;
    for (char c : info.sha256) if (!isxdigit((unsigned char)c)) hashOk = false;
    if (info.url.empty() || !hashOk) {
        // Newer version exists but the manifest carries no verifiable installer.
        // Only nag on a manual check; a silent auto-check stays silent.
        if (manual) { info.url.clear(); g_update = info;
            PostMessageW(g_main, WM_APP_UPDATE_FOUND, 1, (LPARAM)2 /*manual-only*/); }
        return;
    }
    if (!manual && info.version == g_updatePrefs.skipped) return;   // user skipped this one

    g_update = info;
    // Persist the snapshot (mirrors FXChainPlayer's cached-update replay).
    g_updatePrefs.cachedVersion = info.version; g_updatePrefs.cachedUrl = info.url;
    g_updatePrefs.cachedSha256 = info.sha256; g_updatePrefs.cachedSize = info.size;
    g_updatePrefs.cachedChangelog = info.changelog;
    g_updatePrefs.save(updatePrefsPath());
    PostMessageW(g_main, WM_APP_UPDATE_FOUND, (WPARAM)(manual ? 1 : 0), 0);
}

// Worker: download the verified asset to a temp file next to the workspace DB
// (never beside the exe, so a stray write can't clobber the presets ini).
void runUpdateDownload() {
    std::string bytes, err;
    if (!ur::httpGet(widen(g_update.url), bytes, &err, 500LL << 20, updateUserAgent(),
                     updateProgress, nullptr, &g_updateCancel)) {
        postUpdateError(widen(err.empty() ? "download failed" : err));
        return;
    }
    std::string want = g_update.sha256;
    for (char& c : want) c = (char)tolower((unsigned char)c);
    if (ur::sha256Hex(bytes.data(), bytes.size()) != want) {
        postUpdateError(L"the downloaded file is corrupt (checksum mismatch)");
        return;
    }
    std::filesystem::path tmp = appDataDir() / (L"StringRipper-" + widen(g_update.version) + L".exe.download");
    { std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
      out.write(bytes.data(), (std::streamsize)bytes.size());
      if (!out) { postUpdateError(L"could not save the downloaded update"); return; } }
    g_updateDownloadPath = tmp;
    PostMessageW(g_main, WM_APP_UPDATE_DONE, 1, 0);
}

void startUpdateCheck(bool manual) {
    bool expected = false;
    if (!g_updateBusy.compare_exchange_strong(expected, true)) return;
    g_updateManual = manual;
    if (g_updateThread.joinable()) g_updateThread.join();
    g_updateCancel = false;
    g_updateThread = std::thread([manual]{ runUpdateCheck(manual); g_updateBusy = false; });
}
void startUpdateDownload() {
    bool expected = false;
    if (!g_updateBusy.compare_exchange_strong(expected, true)) return;
    g_updateManual = true;
    if (g_updateThread.joinable()) g_updateThread.join();
    g_updateCancel = false;
    g_updateThread = std::thread([]{ runUpdateDownload(); g_updateBusy = false; });
}

/* the selected process as a full-memory minidump, written off the UI thread */
void dumpSelected() {
    const uint32_t pid = selectedPid();
    if (!pid) { MessageBoxW(g_main, L"Choose a process first.", L"Dump", MB_ICONINFORMATION); return; }
    if (pid == GetCurrentProcessId()) { MessageBoxW(g_main, L"StringRipper cannot dump itself.", L"Dump", MB_ICONINFORMATION); return; }
    if (g_dumpThread.joinable()) return;
    std::wstring name = widen(fxchain::ripBackend().processName(pid));
    if (name.empty()) name = L"process";
    wchar_t file[MAX_PATH]{};
    _snwprintf_s(file, _TRUNCATE, L"%s-%u.dmp", std::filesystem::path(name).stem().c_str(), pid);
    OPENFILENAMEW ofn{ sizeof(ofn) };
    ofn.hwndOwner = g_main; ofn.lpstrFile = file; ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = L"Minidump (*.dmp)\0*.dmp\0All files\0*.*\0"; ofn.lpstrDefExt = L"dmp";
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (!GetSaveFileNameW(&ofn)) return;
    g_dumpPath = file;
    EnableWindow(g_dump, FALSE); InvalidateRect(g_dump, nullptr, TRUE);
    SetWindowTextW(g_status, (L"Writing dump of " + name + L"...").c_str());
    g_dumpThread = std::thread([pid, path = g_dumpPath] {
        DWORD err = 0; BOOL ok = FALSE;
        HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!proc) err = GetLastError();
        else {
            HANDLE f = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (f == INVALID_HANDLE_VALUE) err = GetLastError();
            else {
                MINIDUMP_CALLBACK_INFORMATION cb{};
                cb.CallbackRoutine = [](PVOID, PMINIDUMP_CALLBACK_INPUT in, PMINIDUMP_CALLBACK_OUTPUT out) -> BOOL {
                    if (in && out && in->CallbackType == CancelCallback) { out->Cancel = g_closing.load(); out->CheckCancel = TRUE; }
                    return TRUE;    /* closing the window stops a long dump */
                };
                ok = MiniDumpWriteDump(proc, pid, f, (MINIDUMP_TYPE)(MiniDumpWithFullMemory | MiniDumpWithFullMemoryInfo |
                                       MiniDumpWithThreadInfo | MiniDumpWithUnloadedModules), nullptr, nullptr, &cb);
                if (!ok) err = GetLastError();
                CloseHandle(f);
                if (!ok) DeleteFileW(path.c_str());
            }
            CloseHandle(proc);
        }
        PostMessageW(g_main, WM_APP_DUMP_DONE, ok ? 1 : 0, (LPARAM)err);
    });
}
/* load meter: whole-system CPU from the system times, GPU = busiest engine type over all processes */
ULONGLONG ft64(const FILETIME& f) { return (ULONGLONG(f.dwHighDateTime) << 32) | f.dwLowDateTime; }
void sampleLoad() {
    FILETIME i, k, u, c, e, pk, pu;
    if (GetSystemTimes(&i, &k, &u)) {
        const ULONGLONG idle = ft64(i), total = ft64(k) + ft64(u);
        if (g_load.total && total > g_load.total)
            g_load.cpu = 100.0 * (1.0 - double(idle - g_load.idle) / double(total - g_load.total));
        g_load.idle = idle; g_load.total = total;
    }
    const ULONGLONG now = GetTickCount64();
    if (GetProcessTimes(GetCurrentProcess(), &c, &e, &pk, &pu)) {
        const ULONGLONG mine = ft64(pk) + ft64(pu);
        static const unsigned cpus = std::max(1u, std::thread::hardware_concurrency());
        if (g_load.at && now > g_load.at)
            g_load.own = double(mine - g_load.mine) / 100.0 / double(now - g_load.at) / cpus;   /* 100 ns ticks vs ms */
        g_load.mine = mine; g_load.at = now;
    }
    g_load.gpu = g_load.gpuNow;
}
/* GPU like Task Manager: sum each engine over all processes, show the busiest engine. Own thread, PDH can be slow */
void gpuLoop() {
    PDH_HQUERY q = nullptr; PDH_HCOUNTER c = nullptr;
    if (PdhOpenQueryW(nullptr, 0, &q) != ERROR_SUCCESS) return;
    if (PdhAddEnglishCounterW(q, L"\\GPU Engine(*)\\Utilization Percentage", 0, &c) != ERROR_SUCCESS) { PdhCloseQuery(q); return; }
    PdhCollectQueryData(q);
    std::vector<BYTE> buf;
    std::vector<std::pair<std::wstring, double>> perEngine;
    while (WaitForSingleObject(g_load.stop, 1000) == WAIT_TIMEOUT) {
        if (IsIconic(g_main) || PdhCollectQueryData(q) != ERROR_SUCCESS) continue;
        DWORD size = 0, count = 0;
        PDH_STATUS st = PDH_MORE_DATA;
        while (st == PDH_MORE_DATA) {
            st = PdhGetFormattedCounterArrayW(c, PDH_FMT_DOUBLE | PDH_FMT_NOCAP100, &size, &count, nullptr);
            if (st != PDH_MORE_DATA) break;
            buf.resize(size);
            st = PdhGetFormattedCounterArrayW(c, PDH_FMT_DOUBLE | PDH_FMT_NOCAP100, &size, &count, (PDH_FMT_COUNTERVALUE_ITEM_W*)buf.data());
        }
        if (st != ERROR_SUCCESS) { if (st == PDH_NO_DATA || st == PDH_CSTATUS_NO_INSTANCE) g_load.gpuNow = 0; continue; }
        auto* items = (PDH_FMT_COUNTERVALUE_ITEM_W*)buf.data();
        perEngine.clear();
        for (DWORD n = 0; n < count; ++n) {
            if (items[n].FmtValue.CStatus != PDH_CSTATUS_VALID_DATA && items[n].FmtValue.CStatus != PDH_CSTATUS_NEW_DATA) continue;
            const wchar_t* k = wcsstr(items[n].szName, L"luid_");     /* pid_N_luid_X_Y_phys_P_eng_E_engtype_T */
            std::wstring key = k ? k : items[n].szName;
            auto it = std::find_if(perEngine.begin(), perEngine.end(), [&](auto& p) { return p.first == key; });
            if (it == perEngine.end()) perEngine.emplace_back(std::move(key), items[n].FmtValue.doubleValue);
            else it->second += items[n].FmtValue.doubleValue;
        }
        double best = 0;
        for (auto& p : perEngine) best = std::max(best, p.second);
        g_load.gpuNow = std::min(100.0, best);
    }
    PdhCloseQuery(q);
}
void startLoad(HWND hwnd) {
    g_load.stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (g_load.stop) g_load.worker = std::thread(gpuLoop);
    sampleLoad();
    g_load.tip = CreateWindowExW(WS_EX_TOPMOST, TOOLTIPS_CLASSW, nullptr, WS_POPUP | TTS_NOPREFIX | TTS_ALWAYSTIP,
                                 0, 0, 0, 0, hwnd, nullptr, nullptr, nullptr);
    TTTOOLINFOW ti{sizeof(ti)};
    ti.uFlags = TTF_SUBCLASS; ti.hwnd = hwnd; ti.uId = 1; ti.lpszText = LPSTR_TEXTCALLBACKW;
    SendMessageW(g_load.tip, TTM_ADDTOOLW, 0, (LPARAM)&ti);
    SetTimer(hwnd, TIMER_LOAD, 1000, nullptr);
}
std::wstring loadTip() {
    wchar_t t[160];
    _snwprintf_s(t, _TRUNCATE, L"Whole system, refreshed every second.\r\nStringRipper itself: %.1f%% CPU%s",
                 g_load.own, g_load.gpu < 0 ? L"\r\nNo GPU counters on this system." : L"");
    return t;
}
void drawLoad(HDC dc) {
    if (IsRectEmpty(&g_load.rect)) return;
    HFONT of = (HFONT)SelectObject(dc, g_font);
    SetBkMode(dc, TRANSPARENT);
    const int barW = S(34), barH = S(4);
    SIZE ls{}, vs{}; GetTextExtentPoint32W(dc, L"GPU", 3, &ls); GetTextExtentPoint32W(dc, L"100%", 4, &vs);
    const int part = ls.cx + S(6) + barW + S(6) + vs.cx;
    int x = g_load.rect.right - part;
    const int mid = (g_load.rect.top + g_load.rect.bottom) / 2;
    auto one = [&](const wchar_t* name, double v) {
        RECT r{ x, g_load.rect.top, x + ls.cx, g_load.rect.bottom };
        inkText(dc, name, r, g_font, kText3, DT_SINGLELINE | DT_VCENTER);
        RECT bar{ r.right + S(6), mid - barH / 2, r.right + S(6) + barW, mid - barH / 2 + barH };
        roundRect(dc, bar, barH, kBg3, kBg3);
        if (v > 0.5) {
            RECT fill = bar; fill.right = bar.left + std::max(barH, int(barW * std::min(v, 100.0) / 100.0));
            roundRect(dc, fill, barH, kAccent, kAccent);
        }
        wchar_t t[16]; _snwprintf_s(t, _TRUNCATE, L"%d%%", int(v + 0.5));
        RECT vr{ bar.right + S(6), g_load.rect.top, bar.right + S(6) + vs.cx, g_load.rect.bottom };
        inkText(dc, v < 0 ? L"-" : t, vr, g_font, kText2, DT_SINGLELINE | DT_VCENTER | DT_RIGHT);
        x -= part + S(14);
    };
    if (g_load.gpu >= 0) one(L"GPU", g_load.gpu);
    one(L"CPU", g_load.cpu);
    SelectObject(dc, of);
}

void killSelected() {
    const uint32_t pid = selectedPid();
    if (!pid) { MessageBoxW(g_main, L"Choose a process first.", L"Kill", MB_ICONINFORMATION); return; }
    if (pid == GetCurrentProcessId()) { MessageBoxW(g_main, L"That is StringRipper itself.", L"Kill", MB_ICONINFORMATION); return; }
    std::wstring name = widen(fxchain::ripBackend().processName(pid));
    /* one handle from the check to the kill, so a reused pid can't slip in while the dialogs are open */
    HANDLE h = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    const DWORD openErr = h ? 0 : GetLastError();
    const int level = ur::systemProcessLevel(pid, name, h);
    struct Closer { HANDLE& h; ~Closer() { if (h) CloseHandle(h); } } closer{h};
    if (level == 2) {
        MessageBoxW(g_main, (name + L" (pid " + std::to_wstring(pid) + L") is a Windows system process.\r\n\r\n"
            L"Ending it would crash or shut down Windows, so StringRipper does not do that.").c_str(), L"Kill process", MB_ICONSTOP);
        return;
    }
    std::wstring ask = L"End " + name + L" (pid " + std::to_wstring(pid) + L")?\r\n\r\nUnsaved work in that program is lost.";
    if (MessageBoxW(g_main, ask.c_str(), L"Kill process", MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES) return;
    if (level == 1 && MessageBoxW(g_main, (name + L" belongs to Windows or runs as a service.\r\n\r\n"
            L"Ending it can make Windows unstable, freeze the desktop or log you off. End it anyway?").c_str(),
            L"Kill system process", MB_YESNO | MB_ICONSTOP | MB_DEFBUTTON2) != IDYES) return;
    if (!h || !TerminateProcess(h, 1)) {
        const DWORD err = h ? GetLastError() : openErr;
        std::wstring why = L"Could not end " + name + L" (error " + std::to_wstring(err) + L").";
        if (err == ERROR_ACCESS_DENIED && !g_elevated) why += L"\r\n\r\nIt runs with higher rights: start StringRipper as administrator.";
        MessageBoxW(g_main, why.c_str(), L"Kill process", MB_ICONWARNING);
        return;
    }
    WaitForSingleObject(h, 3000);
    autoRefreshProcs();
    SetWindowTextW(g_status, (L"Ended " + name + L" (pid " + std::to_wstring(pid) + L").").c_str());
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        g_main = hwnd;
        g_dpi = (int)GetDpiForWindow(hwnd);
        makeFonts();
        g_bgBrush = CreateSolidBrush(kBg);
        g_bg2Brush = CreateSolidBrush(kBg2);

        g_secSource = mkSection(hwnd, L"SOURCE");
        g_search = CreateWindowExW(0, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL, 0, 0, 0, 0, hwnd, (HMENU)ID_SEARCH, nullptr, nullptr);
        SendMessageW(g_search, EM_SETCUEBANNER, TRUE, (LPARAM)L"Filter processes by name...");
        g_source = CreateWindowExW(0, L"COMBOBOX", L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | CBS_OWNERDRAWFIXED | CBS_HASSTRINGS | WS_VSCROLL,
            0, 0, 0, 0, hwnd, (HMENU)ID_SOURCE, nullptr, nullptr);
        SetWindowTheme(g_source, L"DarkMode_CFD", nullptr);
        g_refresh = mkPush(hwnd, L"Refresh", ID_REFRESH);
        g_file = mkPush(hwnd, L"File...", ID_FILE);
        g_settingsButton = mkPush(hwnd, L"Scan settings...", ID_SCAN_SETTINGS);
        g_allInst = mkChip(hwnd, L"All instances", ID_ALL_INSTANCES);
        setChecked(g_allInst, false);
        g_dump = mkPush(hwnd, L"Dump...", ID_DUMP);
        g_kill = mkPush(hwnd, L"Kill...", ID_KILL);
        g_srcInfo = mkStatic(hwnd, L"Drop files or folders on the window, or scan the selected process.");

        g_secFind = mkSection(hwnd, L"WHAT TO FIND");
        g_modeUrl = mkButton(hwnd, L"URLs", ID_MODE_URL, BS_OWNERDRAW | WS_GROUP);
        g_modeRegex = mkButton(hwnd, L"Regex", ID_MODE_REGEX, BS_OWNERDRAW);
        setChecked(g_modeUrl, true);
        setChecked(g_modeRegex, false);
        g_urlHint = mkStatic(hwnd, L"Finds http, https, ftp, ws, wss, rtsp, rtmp and udp links, grouped by domain.");
        g_crap = mkChip(hwnd, L"Crap filter", ID_CRAP);
        setChecked(g_crap, true);

        g_presetLabel = mkStatic(hwnd, L"Preset:");
        g_pEmail = mkChip(hwnd, L"Email", ID_P_EMAIL);
        g_pIpv4 = mkChip(hwnd, L"IPv4", ID_P_IPV4);
        g_pIpv6 = mkChip(hwnd, L"IPv6", ID_P_IPV6);
        g_pGuid = mkChip(hwnd, L"GUID", ID_P_GUID);
        g_pApi = mkChip(hwnd, L"API key", ID_P_APIKEY);
        g_pPath = mkChip(hwnd, L"File path", ID_P_PATH);
        g_pDl = mkChip(hwnd, L"Download", ID_P_DL);
        for (HWND h : {g_pEmail, g_pIpv4, g_pIpv6, g_pGuid, g_pApi, g_pPath, g_pDl}) setChecked(h, h == g_pEmail);
        g_customLabel = mkStatic(hwnd, L"Custom:");
        g_custom = CreateWindowExW(0, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL, 0, 0, 0, 0, hwnd, (HMENU)ID_CUSTOM, nullptr, nullptr);
        SendMessageW(g_custom, EM_SETCUEBANNER, TRUE, (LPARAM)L"your own regex (ECMAScript)...");
        g_presets = mkPush(hwnd, L"Edit user presets...", ID_PRESETS);
        g_presetPick = CreateWindowExW(0, L"COMBOBOX", L"",
            WS_CHILD | WS_TABSTOP | CBS_DROPDOWNLIST | CBS_OWNERDRAWFIXED | CBS_HASSTRINGS | WS_VSCROLL,
            0, 0, 0, 0, hwnd, (HMENU)ID_PRESET_PICK, nullptr, nullptr);
        SetWindowTheme(g_presetPick, L"DarkMode_CFD", nullptr);
        SendMessageW(g_presetPick, WM_SETFONT, (WPARAM)g_font, FALSE);
        roundDrop(g_presetPick, 4); roundDrop(g_source, 1);

        g_secDecode = mkSection(hwnd, L"DECODE");
        g_ascii = mkChip(hwnd, L"ASCII", ID_ENC_ASCII);
        g_utf16 = mkChip(hwnd, L"UTF-16", ID_ENC_UTF16);
        g_b64 = mkChip(hwnd, L"Base64", ID_ENC_B64);
        g_hex = mkChip(hwnd, L"Hex", ID_ENC_HEX);
        g_esc = mkChip(hwnd, L"Escaped", ID_ENC_ESC);
        for (HWND h : {g_ascii, g_utf16, g_b64, g_hex, g_esc}) setChecked(h, true);

        g_scan = mkPush(hwnd, L"Scan", ID_SCAN);
        g_pause = mkPush(hwnd, L"Pause", ID_PAUSE);
        g_cancel = mkPush(hwnd, L"Cancel", ID_CANCEL);
        g_monitor = mkChip(hwnd, L"Live", ID_MONITOR);
        g_monitorInterval = CreateWindowExW(0, L"EDIT", L"5", WS_CHILD | WS_VISIBLE | WS_TABSTOP |
            ES_NUMBER | ES_CENTER | WS_BORDER, 0, 0, 0, 0, hwnd, (HMENU)ID_MONITOR_INTERVAL, nullptr, nullptr);
        SendMessageW(g_monitorInterval, EM_SETLIMITTEXT, 4, 0);
        EnableWindow(g_pause, FALSE); EnableWindow(g_cancel, FALSE);
        g_status = mkStatic(hwnd, L"Ready.");

        g_secResults = mkSection(hwnd, L"RESULTS");
        g_filter = CreateWindowExW(0, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL, 0, 0, 0, 0, hwnd, (HMENU)ID_FILTER, nullptr, nullptr);
        SendMessageW(g_filter, EM_SETCUEBANNER, TRUE, (LPARAM)L"Filter results...");
        g_newOnly = mkChip(hwnd, L"New only", ID_NEW_ONLY);
        g_ignoreChip = mkChip(hwnd, L"Ignore list", ID_IGNORE);
        setChecked(g_ignoreChip, true);
        g_workspace = mkPush(hwnd, L"Workspace...", ID_WORKSPACE);
        g_dashboard = mkPush(hwnd, L"Dashboard", ID_DASHBOARD);
        setChecked(g_newOnly, false); EnableWindow(g_newOnly, FALSE);
        g_results = CreateWindowExW(0, WC_LISTVIEWW, L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SHOWSELALWAYS | LVS_OWNERDATA,
            0, 0, 0, 0, hwnd, (HMENU)ID_RESULTS, nullptr, nullptr);
        ListView_SetExtendedListViewStyle(g_results, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
        SetWindowTheme(g_results, L"DarkMode_Explorer", nullptr);
        ListView_SetBkColor(g_results, kCard);
        ListView_SetTextBkColor(g_results, kCard);
        ListView_SetTextColor(g_results, kText);
        LVCOLUMNW col{};
        col.mask = LVCF_TEXT | LVCF_WIDTH;
        col.cx = 520; col.pszText = (LPWSTR)L"Value"; ListView_InsertColumn(g_results, 0, &col);
        col.cx = 90;  col.pszText = (LPWSTR)L"Encoding"; ListView_InsertColumn(g_results, 1, &col);
        col.cx = 220; col.pszText = (LPWSTR)L"Source"; ListView_InsertColumn(g_results, 2, &col);
        col.cx = 115; col.pszText = (LPWSTR)L"Offset"; ListView_InsertColumn(g_results, 3, &col);

        g_copy = mkPush(hwnd, L"Copy selected", ID_COPY);
        g_save = mkPush(hwnd, L"Export...", ID_SAVE);
        g_editor = mkPush(hwnd, L"Send to editor", ID_EDITOR);
        g_clear = mkPush(hwnd, L"Clear", ID_CLEAR);
        g_pagePrev = mkPush(hwnd, L"Previous", ID_PAGE_PREV);
        g_pageNext = mkPush(hwnd, L"Next", ID_PAGE_NEXT);
        g_pageLabel = mkStatic(hwnd, L"1 / 1");
        for (HWND h : {g_pagePrev, g_pageNext, g_pageLabel}) ShowWindow(h, SW_HIDE);   // one list now, no pages
        g_about = mkPush(hwnd, L"About", ID_ABOUT);
        enableResultActions(false);

        applyFonts();

        for (HWND h : {g_search, g_custom, g_filter}) SetWindowTheme(h, L"", L"");

        darkTitle(hwnd);

        /* drop */
        for (HWND h : {hwnd, g_results}) {
            DragAcceptFiles(h, TRUE);
            for (int m : {WM_DROPFILES, WM_COPYDATA, 0x0049 /*WM_COPYGLOBALDATA*/})
                ChangeWindowMessageFilterEx(h, (UINT)m, MSGFLT_ALLOW, nullptr);
        }
        SetWindowSubclass(g_results, resultsSub, 0, 0);

        MONITORINFO mi{ sizeof(mi) };
        GetMonitorInfoW(MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST), &mi);
        int ww = std::min<int>(S(1000), mi.rcWork.right - mi.rcWork.left);
        int wh = std::min<int>(S(760), mi.rcWork.bottom - mi.rcWork.top);
        SetWindowPos(hwnd, nullptr, mi.rcWork.left + (mi.rcWork.right - mi.rcWork.left - ww) / 2,
                     mi.rcWork.top + (mi.rcWork.bottom - mi.rcWork.top - wh) / 2, ww, wh, SWP_NOZORDER);

        refreshProcesses();
        updateModeVisibility();
        g_presetPath = presetFilePath();
        std::error_code presetEc;
        std::filesystem::path backupPath = g_presetPath; backupPath += L".bak";
        if (std::filesystem::exists(g_presetPath, presetEc) || std::filesystem::exists(backupPath, presetEc)) {
            std::string e;
            bool loaded = ur::loadUserPresets(g_presetPath, g_userPresets, &e);
            bool recovered = false;
            if (!loaded) {
                std::filesystem::path bak = g_presetPath; bak += L".bak";
                std::string backupError;
                recovered = ur::loadUserPresets(bak, g_userPresets, &backupError);
                loaded = recovered;
            }
            if (loaded && !g_userPresets.empty()) {
                if (recovered) SetWindowTextW(g_status, L"Preset file was invalid; loaded the .bak copy.");
            } else if (!e.empty())
                SetWindowTextW(g_status, widen(std::string("Preset file: ") + e).c_str());
        }
        fillPresetPick();
        RegisterDragDrop(g_filter, &g_filterDrop);
        SetTimer(hwnd, TIMER_PROCS, 2000, nullptr);
        startLoad(hwnd);
        if (g_autoRipPid) {
            selectPid(g_autoRipPid);
            PostMessageW(hwnd, WM_COMMAND, ID_SCAN, 0);
        } else if (!g_autoRipPaths.empty()) {
            setSourcePaths(g_autoRipPaths);
            PostMessageW(hwnd, WM_COMMAND, ID_SCAN, 0);
        }
        return 0;
    }
    case WM_SIZE:
        layout(LOWORD(lp), HIWORD(lp));
        return 0;
    case WM_TIMER:
        if (wp == TIMER_PROGRESS) {
            wchar_t s[128];
            if (g_cancelFlag) wcscpy_s(s, L"Cancelling...");
            else if (g_scanGate.paused()) wcscpy_s(s, L"Paused");
            else if (g_progress.planning) wcscpy_s(s, L"Preparing scan...");
            else _snwprintf_s(s, _TRUNCATE, L"%s %.2f%%  (%.2f / %.2f MiB)%s",
                g_progress.merging ? L"Finalizing..." : L"Scanning...",
                g_progress.percent(), (g_progress.completed.load() + g_progress.skipped.load()) / 1048576.0,
                g_progress.total.load() / 1048576.0,
                g_progress.skipped.load() ? L"  (unreadable bytes skipped)" : L"");
            SetWindowTextW(g_status, s);
        } else if (wp == TIMER_PROCS) {
            autoRefreshProcs();
        } else if (wp == TIMER_LOAD) {
            if (IsIconic(hwnd)) return 0;
            sampleLoad();
            if (!IsRectEmpty(&g_load.rect)) InvalidateRect(hwnd, &g_load.rect, TRUE);
        } else if (wp == TIMER_MONITOR) {
            KillTimer(hwnd, TIMER_MONITOR);
            if (isChecked(g_monitor) && !g_scanning) doScan();
        }
        return 0;
    case WM_GETMINMAXINFO: {
        auto* mmi = (MINMAXINFO*)lp;
        mmi->ptMinTrackSize.x = S(820);
        mmi->ptMinTrackSize.y = S(600);
        return 0;
    }
    case WM_DPICHANGED: {
        g_dpi = HIWORD(wp);
        makeFonts();
        applyFonts();
        const RECT* r = (const RECT*)lp;
        SetWindowPos(hwnd, nullptr, r->left, r->top, r->right - r->left, r->bottom - r->top,
                     SWP_NOZORDER | SWP_NOACTIVATE);
        return 0;
    }
    case WM_CTLCOLORSTATIC: {
        HDC dc = (HDC)wp;
        HWND ctl = (HWND)lp;
        SetTextColor(dc, (ctl == g_secSource || ctl == g_secFind || ctl == g_secDecode ||
                          ctl == g_secResults || ctl == g_srcInfo || ctl == g_urlHint)
                         ? kText3 : kText);
        SetBkColor(dc, kBg);
        return (LRESULT)g_bgBrush;
    }
    case WM_CTLCOLORBTN: {
        HDC dc = (HDC)wp;
        SetTextColor(dc, kText);
        SetBkColor(dc, kBg);
        return (LRESULT)g_bgBrush;
    }
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORLISTBOX: {
        HDC dc = (HDC)wp;
        SetTextColor(dc, kText);
        SetBkColor(dc, kBg2);
        return (LRESULT)g_bg2Brush;
    }
    case WM_DRAWITEM: {
        auto* d = (const DRAWITEMSTRUCT*)lp;
        if (d->CtlType == ODT_COMBOBOX) drawCombo(d);
        else if (d->CtlType == ODT_STATIC) drawSection(d);
        else if (isMode(d->hwndItem)) drawMode(d);
        else if (isChip(d->hwndItem)) drawChip(d);
        else drawPush(d);
        return TRUE;
    }
    case WM_MEASUREITEM:
        ((MEASUREITEMSTRUCT*)lp)->itemHeight = S(22);
        return TRUE;
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(hwnd, &ps);
        roundRect(dc, g_segRect, S(20), kBg, kBSub);
        for (int i = 0; i < 5; ++i) {
            if ((i == 2 && !IsWindowVisible(g_custom)) || (i == 4 && !IsWindowVisible(g_presetPick))) continue;
            roundRect(dc, g_fields[i], S(20), kBg2, kBSub);
        }
        roundRect(dc, g_listCard, S(26), kCard, kBSub);
        drawLoad(dc);
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_ERASEBKGND: {
        RECT rc; GetClientRect(hwnd, &rc);
        FillRect((HDC)wp, &rc, g_bgBrush);
        return 1;
    }
    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case ID_SEARCH: if (HIWORD(wp) == EN_CHANGE) { if (g_procsStale) syncProcs(); applyProcFilter(); } break;
        case ID_FILTER: if (HIWORD(wp) == EN_CHANGE && !g_filterQuiet) applyResultFilter(false); break;
        case ID_REFRESH: refreshProcesses(); break;
        case ID_FILE: pickFile(); break;
        case ID_SCAN_SETTINGS: showScanSettings(); break;
        case ID_PRESETS: showPresetEditor(); break;
        case ID_WORKSPACE: showWorkspace(); break;
        case ID_DASHBOARD: showDashboard(); break;
        case ID_MODE_URL: case ID_MODE_REGEX: switchMode(LOWORD(wp) == ID_MODE_REGEX); break;
        case ID_PRESET_PICK:
            if (HIWORD(wp) == CBN_SELCHANGE) {
                int sel = (int)SendMessageW(g_presetPick, CB_GETCURSEL, 0, 0);
                if (sel > 0 && sel <= (int)g_userPresets.size()) applyUserPreset(g_userPresets[sel - 1]);
            }
            break;
        case ID_DUMP: dumpSelected(); break;
        case ID_KILL: killSelected(); break;
        case ID_SCAN: doScan(); break;
        case ID_PAUSE:
            g_scanGate.setPaused(!g_scanGate.paused());
            SetWindowTextW(g_pause, g_scanGate.paused() ? L"Resume" : L"Pause");
            break;
        case ID_MONITOR:
            setChecked(g_monitor, !isChecked(g_monitor));
            if (!isChecked(g_monitor)) KillTimer(hwnd, TIMER_MONITOR);
            break;
        case ID_CANCEL: g_cancelFlag = true; g_scanGate.setPaused(false); SetWindowTextW(g_status, L"Cancelling..."); break;
        case ID_COPY: copySelected(); break;
        case ID_SAVE: saveAsTxt(); break;
        case ID_EDITOR: sendToEditor(); break;
        case ID_ABOUT: showAbout(); break;
        case ID_CLEAR: clearResults(); break;
        case ID_NEW_ONLY:
            setChecked(g_newOnly, !isChecked(g_newOnly)); applyResultFilter(); break;
        case ID_ALL_INSTANCES: setChecked(g_allInst, !isChecked(g_allInst)); break;
        case ID_IGNORE: setChecked(g_ignoreChip, !isChecked(g_ignoreChip)); applyResultFilter(); break;
        case ID_ENC_ASCII: case ID_ENC_UTF16: case ID_ENC_B64: case ID_ENC_HEX: case ID_ENC_ESC:
        case ID_P_EMAIL: case ID_P_IPV4: case ID_P_IPV6:
        case ID_P_GUID: case ID_P_APIKEY: case ID_P_PATH: case ID_P_DL: case ID_CRAP: {
            HWND c = (HWND)lp;
            setChecked(c, !isChecked(c));
            if (!g_applyingPreset) g_activePreset.clear();
            break;
        }
        case ID_CUSTOM:
            if (HIWORD(wp) == EN_CHANGE) {
                if (!g_applyingPreset) { g_activePreset.clear(); SendMessageW(g_presetPick, CB_SETCURSEL, 0, 0); }
                if (GetWindowTextLengthW(g_custom) > 0) setRegexMode();
            }
            break;
        case ID_SOURCE:
            if (HIWORD(wp) == CBN_DROPDOWN) syncProcs();
            if (HIWORD(wp) == CBN_SELCHANGE) {
                g_chosenPaths.clear();
                int sel = (int)SendMessageW(g_source, CB_GETCURSEL, 0, 0);
                if (sel >= 0 && sel < (int)g_procsView.size())
                    SetWindowTextW(g_srcInfo, (L"Scanning process: " + widen(g_procsView[sel].name) +
                        L"   (or pick a file)").c_str());
            }
            break;
        }
        return 0;
    case WM_DROPFILES:
        onDrop((HDROP)wp);
        return 0;
    case WM_COPYDATA: {
        auto* cds = (COPYDATASTRUCT*)lp;
        if (!cds || cds->dwData != kDropMagic) break;
        const auto names = ur::parsePathHandoff(cds->lpData, cds->cbData);
        std::vector<std::filesystem::path> paths;
        for (const auto& name : names) paths.emplace_back(name);
        if (!paths.empty() && !g_scanning) {
            setSourcePaths(std::move(paths));
            SetForegroundWindow(hwnd);
            PostMessageW(hwnd, WM_COMMAND, ID_SCAN, 0);
        }
        return TRUE;
    }
    case WM_NOTIFY: {
        auto* hdr = (NMHDR*)lp;
        if (hdr->hwndFrom == g_load.tip && hdr->code == TTN_GETDISPINFOW) {
            static std::wstring tip; tip = loadTip();
            SendMessageW(g_load.tip, TTM_SETMAXTIPWIDTH, 0, S(360));
            ((NMTTDISPINFOW*)lp)->lpszText = (LPWSTR)tip.c_str();
            return 0;
        }
        if (hdr->idFrom == ID_RESULTS && hdr->code == NM_RCLICK) {
            const int row = ((NMITEMACTIVATE*)lp)->iItem;
            if (row >= 0 && row < (int)g_rows.size() && g_rows[row].item < 0) {
                const int group = g_rows[row].group;
                HMENU menu = CreatePopupMenu();
                AppendMenuW(menu, MF_STRING, 1, (L"Copy all (" + std::to_wstring(g_viewResults[group].items.size()) + L")").c_str());
                POINT p; GetCursorPos(&p);
                const std::string host = g_viewResults[group].name;
                const int chosen = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, p.x, p.y, 0, g_main, nullptr);
                DestroyMenu(menu);
                if (chosen == 1)        /* a live rescan may have moved the groups while the menu was open */
                    for (int i = 0; i < (int)g_viewResults.size(); ++i)
                        if (g_viewResults[i].name == host) { copyGroup(i); break; }
                return 0;
            }
        }
        if (hdr->idFrom == ID_RESULTS && (hdr->code == NM_DBLCLK || hdr->code == NM_RCLICK)) {
            auto* action = (NMITEMACTIVATE*)lp;
            if (const auto* f = findingAtRow(action->iItem)) {
                if (hdr->code == NM_DBLCLK) showFindingDetails(*f);
                else showFindingMenu(*f);
            }
            return 0;
        }
        if (hdr->idFrom == ID_RESULTS && hdr->code == LVN_GETDISPINFOW) {
            auto* di = (NMLVDISPINFOW*)lp;
            if ((di->item.mask & LVIF_TEXT) && di->item.pszText && di->item.cchTextMax > 0) {
                std::wstring t = rowText(di->item.iItem, di->item.iSubItem);
                wcsncpy_s(di->item.pszText, di->item.cchTextMax, t.c_str(), _TRUNCATE);
            }
            return 0;
        }
        if (hdr->idFrom == ID_RESULTS && hdr->code == LVN_ODFINDITEMW) {
            return -1;      /* no type-ahead: keep the selection where it is */
        }
        if (hdr->idFrom == ID_RESULTS && hdr->code == LVN_BEGINDRAG) {
            dragText(rowText(((NMLISTVIEW*)lp)->iItem, 0));
            return 0;
        }
        auto* cd = (NMLVCUSTOMDRAW*)lp;
        if (cd->nmcd.hdr.idFrom != ID_RESULTS || cd->nmcd.hdr.code != NM_CUSTOMDRAW) break;
        if (cd->nmcd.dwDrawStage == CDDS_PREPAINT) return CDRF_NOTIFYITEMDRAW;
        if (cd->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {
            drawResultRow(cd->nmcd.hdr.hwndFrom, cd->nmcd.hdc, (int)cd->nmcd.dwItemSpec);
            return CDRF_SKIPDEFAULT;
        }
        return CDRF_DODEFAULT;
    }
    case WM_APP_DONE:
        onDone((std::vector<ur::Group>*)lp);
        return 0;
    case WM_APP_DUMP_DONE: {
        if (g_dumpThread.joinable()) g_dumpThread.join();
        EnableWindow(g_dump, !g_scanning); InvalidateRect(g_dump, nullptr, TRUE);
        if (wp) {
            std::error_code ec;
            const auto mb = std::filesystem::file_size(g_dumpPath, ec) / (1024 * 1024);
            SetWindowTextW(g_status, (L"Dump written: " + g_dumpPath + L"  (" + std::to_wstring(mb) + L" MB)").c_str());
        } else {
            std::wstring why = L"Could not write the dump (error " + std::to_wstring((DWORD)lp) + L").";
            if ((DWORD)lp == ERROR_ACCESS_DENIED && !g_elevated) why += L"\r\n\r\nIt runs with higher rights: start StringRipper as administrator.";
            SetWindowTextW(g_status, L"Dump failed.");
            MessageBoxW(hwnd, why.c_str(), L"Dump", MB_ICONWARNING);
        }
        return 0;
    }
    case WM_APP_UPDATE_FOUND: {
        const bool manualOnly = lp == 2;
        std::wstring msg = L"StringRipper " + widen(g_update.version) +
            L" is available (you have " STRINGRIPPER_VERSION L").\r\n\r\n";
        if (!g_update.changelog.empty()) msg += widen(g_update.changelog) + L"\r\n\r\n";
        if (manualOnly) {
            msg += L"Open the download page?";
            if (MessageBoxW(hwnd, msg.c_str(), L"Update available", MB_YESNO | MB_ICONINFORMATION) == IDYES)
                ShellExecuteW(hwnd, L"open", g_update.notes.empty() ? kReleasesPageUrl
                              : widen(g_update.notes).c_str(), nullptr, nullptr, SW_SHOWNORMAL);
            return 0;
        }
        msg += L"Yes: update now.   No: later.   Cancel: skip this version.";
        int r = MessageBoxW(hwnd, msg.c_str(), L"Update available", MB_YESNOCANCEL | MB_ICONINFORMATION);
        if (r == IDYES) {
            SetWindowTextW(g_status, L"Downloading update...");
            startUpdateDownload();
        } else if (r == IDCANCEL) {
            g_updatePrefs.skipped = g_update.version;
            g_updatePrefs.save(updatePrefsPath());
        }
        return 0;
    }
    case WM_APP_UPDATE_PROGRESS: {
        wchar_t s[64]; _snwprintf_s(s, _TRUNCATE, L"Downloading update... %d%%", (int)wp);
        SetWindowTextW(g_status, s);
        return 0;
    }
    case WM_APP_UPDATE_UPTODATE:
        MessageBoxW(hwnd, L"You are on the latest version.", L"StringRipper", MB_OK | MB_ICONINFORMATION);
        return 0;
    case WM_APP_UPDATE_DONE: {
        if (wp == 1) {
            if (g_updateThread.joinable()) g_updateThread.join();
            std::string err;
            if (ur::selfReplace(g_updateDownloadPath, g_update.sha256, &err)) {
                // Release the single-instance mutex first, or the relaunched
                // exe collides with this still-closing one and bows out.
                if (g_instanceMutex) { ReleaseMutex(g_instanceMutex); CloseHandle(g_instanceMutex); g_instanceMutex = nullptr; }
                ur::relaunchSelf();
                DestroyWindow(hwnd);
            } else {
                std::error_code ec; std::filesystem::remove(g_updateDownloadPath, ec);
                std::wstring m = L"Could not install the update: " + widen(err) +
                    L"\r\n\r\nOpen the download page instead?";
                SetWindowTextW(g_status, L"Update could not be installed");
                if (MessageBoxW(hwnd, m.c_str(), L"Update", MB_YESNO | MB_ICONWARNING) == IDYES)
                    ShellExecuteW(hwnd, L"open", kReleasesPageUrl, nullptr, nullptr, SW_SHOWNORMAL);
            }
        } else {
            wchar_t* m = (wchar_t*)lp;
            SetWindowTextW(g_status, L"Update check failed");
            if (g_updateManual)
                MessageBoxW(hwnd, m ? m : L"Update failed.", L"Update", MB_OK | MB_ICONWARNING);
            free(m);
        }
        return 0;
    }
    case WM_DESTROY:
        g_cancelFlag = true; g_closing = true;
        g_updateCancel = true;
        g_scanGate.setPaused(false);
        RevokeDragDrop(g_filter);
        if (g_scanThread.joinable()) g_scanThread.join();
        if (g_dumpThread.joinable()) g_dumpThread.join();
        if (g_updateThread.joinable()) g_updateThread.join();
        if (!g_updateDownloadPath.empty()) {
            std::error_code ec; std::filesystem::remove(g_updateDownloadPath, ec);
        }
        { MSG pending{};
          while (PeekMessageW(&pending, hwnd, WM_APP_UPDATE_DONE, WM_APP_UPDATE_DONE, PM_REMOVE))
              if (pending.wParam == 0) free((wchar_t*)pending.lParam); }
        { MSG pending{};
          while (PeekMessageW(&pending, hwnd, WM_APP_DONE, WM_APP_DONE, PM_REMOVE))
              delete (std::vector<ur::Group>*)pending.lParam; }
        KillTimer(hwnd, TIMER_PROGRESS);
        KillTimer(hwnd, TIMER_PROCS);
        KillTimer(hwnd, TIMER_MONITOR);
        KillTimer(hwnd, TIMER_LOAD);
        if (g_load.worker.joinable()) { SetEvent(g_load.stop); g_load.worker.join(); }
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

int runGui(HINSTANCE hInst) {
    OleInitialize(nullptr);
    LoadLibraryW(L"Msftedit.dll");
    INITCOMMONCONTROLSEX icc{ sizeof(icc), ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES };
    InitCommonControlsEx(&icc);

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = CreateSolidBrush(kBg);
    wc.lpszClassName = L"StringRipperWindow";
    wc.hIcon = LoadIconW(hInst, MAKEINTRESOURCEW(1));
    wc.hIconSm = LoadIconW(hInst, MAKEINTRESOURCEW(1));
    RegisterClassExW(&wc);

    std::wstring title = L"StringRipper " STRINGRIPPER_VERSION L" by Akustikrausch";
    if (g_elevated) title += L"   [admin]";
    g_main = CreateWindowExW(0, wc.lpszClassName, title.c_str(),
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN, CW_USEDEFAULT, CW_USEDEFAULT, 1000, 760,
        nullptr, nullptr, hInst, nullptr);
    if (!g_main) return 1;
    ShowWindow(g_main, SW_SHOW);
    UpdateWindow(g_main);

    /* auto-update: clear a leftover ".old" from a prior self-replace, then, once
       the user has answered the first-run consent, check GitHub in the
       background. Presets and workspace are never touched by an update. */
    loadIgnoreRules();
    ur::cleanupSelfReplace();
    g_updatePrefs.load(updatePrefsPath());
    if (!g_updatePrefs.asked) {
        int r = MessageBoxW(g_main,
            L"StringRipper can check GitHub for a newer version on startup and "
            L"install it for you.\r\n\r\nYour presets and saved scans are kept.\r\n\r\n"
            L"Check for updates automatically?",
            L"StringRipper updates", MB_YESNO | MB_ICONQUESTION);
        g_updatePrefs.autoCheck = (r == IDYES);
        g_updatePrefs.asked = true;
        g_updatePrefs.save(updatePrefsPath());
    }
    if (g_updatePrefs.autoCheck) startUpdateCheck(false);

    MSG m;
    while (GetMessageW(&m, nullptr, 0, 0) > 0) {
        if (m.message == WM_KEYDOWN && m.wParam == VK_ESCAPE) {    /* Esc closes what has nothing to save */
            HWND root = GetAncestor(m.hwnd, GA_ROOT);
            if (root && (root == g_inspector || root == g_dashboardWindow || root == g_ws)) { PostMessageW(root, WM_CLOSE, 0, 0); continue; }
        }
        if (g_pe && IsDialogMessageW(g_pe, &m)) continue;
        if (IsDialogMessageW(g_main, &m)) continue;
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }
    return 0;
}

} // namespace

static void forwardPaths(HWND ex, const std::vector<std::filesystem::path>& paths) {
    std::wstring buf;
    for (const auto& p : paths) { buf += p.wstring(); buf.push_back(L'\0'); }
    buf.push_back(L'\0');
    COPYDATASTRUCT cds{ kDropMagic, (DWORD)(buf.size() * sizeof(wchar_t)), (PVOID)buf.data() };
    SendMessageW(ex, WM_COPYDATA, 0, (LPARAM)&cds);
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int) {
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    g_elevated = elevated();
    bool cliFlag = false;
    for (int i = 1; i < __argc; ++i) {
        std::wstring a = __wargv[i];
        if (a == L"--rip-pid" && i + 1 < __argc) g_autoRipPid = (uint32_t)wcstoul(__wargv[++i], nullptr, 10);
        else if (!a.empty() && (a[0] == L'-' || a == L"/?")) cliFlag = true;
        else {
            std::error_code ec;
            if (std::filesystem::exists(std::filesystem::path(a), ec)) g_autoRipPaths.emplace_back(a);
            else cliFlag = true;
        }
    }
    if (cliFlag && !g_autoRipPid) return runCli(__argc, __wargv);

    /* one GUI instance: a second launch hands its dropped paths to the first
       and bows out, so scans never race each other. */
    HANDLE mtx = CreateMutexW(nullptr, TRUE, L"StringRipper.SingleInstance.v1");
    const DWORD mutexError = GetLastError();
    if (mutexError == ERROR_ALREADY_EXISTS || (!mtx && mutexError == ERROR_ACCESS_DENIED)) {
        HWND ex = FindWindowW(L"StringRipperWindow", nullptr);
        if (ex) {
            if (IsIconic(ex)) ShowWindow(ex, SW_RESTORE);
            SetForegroundWindow(ex);
            if (!g_autoRipPaths.empty()) forwardPaths(ex, g_autoRipPaths);
        }
        return 0;
    }
    g_instanceMutex = mtx;
    return runGui(hInst);
}
