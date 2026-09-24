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
#include <dwmapi.h>
#include <uxtheme.h>

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
#include "regex_presets.hpp"
#include "result_tools.hpp"
#include "scan_driver.hpp"
#include "file_read.hpp"
#include "scan_service.hpp"
#include "process_scan_win32.hpp"
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
#pragma comment(lib, "uxtheme.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
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

static std::string resultsToText(const std::vector<ur::Group>& groups, ur::Mode) {
    std::string out;
    for (const auto& g : groups) {
        if (!out.empty()) out += "\r\n";
        out += g.name + "  (" + std::to_string(g.items.size()) + ")\r\n\r\n";
        for (const auto& f : g.items) out += f.value + "\r\n";
    }
    return out;
}

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
    if (::AttachConsole(ATTACH_PARENT_PROCESS)) {
        FILE* f = nullptr;
        freopen_s(&f, "CONOUT$", "w", stdout);
        freopen_s(&f, "CONOUT$", "w", stderr);
    }
    ur::Options o;
    ur::PresetCli preset;
    try {
        std::vector<std::string> args;
        for (int i = 1; i < argc; ++i) args.push_back(narrow(argv[i]));
        preset = ur::presetCli(args, ur::executablePresets(argv[0]));
        o = preset.options;
    } catch (const std::exception& e) { std::fprintf(stderr, "error: %s\n", e.what()); return 2; }
    std::vector<std::filesystem::path> inputs;
    uint32_t pid = 0;
    std::wstring outFile;
    std::string format = "txt";
    bool help = false;

    auto next = [&](int& i) -> std::wstring { return (i + 1 < argc) ? argv[++i] : std::wstring(); };
    for (int i = 1; i < argc; ++i) {
        std::wstring a = argv[i];
        if (a == L"--help" || a == L"-h" || a == L"/?") help = true;
        else if (a == L"--cli") {}
        else if (a == L"--file" || a == L"--folder") inputs.push_back(next(i));
        else if (a == L"--pid") pid = (uint32_t)std::wcstoul(next(i).c_str(), nullptr, 10);
        else if (a == L"--regex") {
            o.mode = ur::Mode::Regex; o.customRegex = narrow(next(i).c_str()); o.customLabel = "Custom";
            o.presets.clear(); o.extraPatterns.clear();
        }
        else if (a == L"--preset") {
            o.mode = ur::Mode::Regex; o.presets = splitCsv(narrow(next(i).c_str()));
            o.customRegex.clear(); o.extraPatterns.clear();
        }
        else if (a == L"--scheme") o.schemes = splitCsv(narrow(next(i).c_str()));
        else if (a == L"--icase") o.caseInsensitive = true;
        else if (a == L"--no-ascii") o.ascii = false;
        else if (a == L"--no-utf16") o.utf16 = false;
        else if (a == L"--no-base64") o.base64 = false;
        else if (a == L"--no-hex") o.hex = false;
        else if (a == L"--out") outFile = next(i);
        else if (a == L"--format") format = narrow(next(i).c_str());
        else if (a == L"--user-preset" || a == L"--presets-file") next(i);
        else if (a == L"--list-user-presets") {}
        else if (a == L"--no-crap") o.dropCrap = false;
        else { std::fprintf(stderr, "error: unknown option %s\n", narrow(a.c_str()).c_str()); return 2; }
    }

    if (format != "txt" && format != "csv" && format != "json") {
        std::fprintf(stderr, "error: format must be txt, csv or json\n"); return 2;
    }
    if (preset.list && !help) {
        for (const auto& p : preset.presets) std::printf("%s\n", p.name.c_str());
        return 0;
    }

    if (help || (inputs.empty() && pid == 0)) {
        std::printf(
            "StringRipper " STRINGRIPPER_VERSION " - extract URLs or regex matches from processes and files.\n\n"
            "Usage:\n"
            "  StringRipper.exe --pid N            [options]   scan a running process\n"
            "  StringRipper.exe --file PATH ...    [options]   scan files\n"
            "  StringRipper.exe --folder PATH ...  [options]   scan a folder (recursive)\n\n"
            "Options:\n"
            "  --regex PAT      regex mode with a custom ECMAScript pattern\n"
            "  --preset IDS     regex mode with presets (email,ipv4,ipv6,guid,apikey,filepath)\n"
            "  --scheme LIST    URL mode: only these schemes (e.g. http,https)\n"
            "  --icase          case-insensitive matching\n"
            "  --no-ascii --no-utf16 --no-base64 --no-hex   turn off a decoder\n"
            "  --out FILE       write results to FILE (never uses the clipboard)\n\n"
            "  --format TYPE    txt (default), csv or json\n"
            "  --user-preset NAME       load a saved regex user preset\n"
            "  --list-user-presets      list saved preset names and exit\n"
            "  --presets-file PATH      INI location (default: next to executable)\n\n"
            "Runs as the invoking user. A target that needs more rights is offered an\n"
            "elevated relaunch in the GUI; from a shell, start an elevated one yourself.\n\n"
            "Reading a process reuses FXChainPlayer's ripper backend; scanning is multi-threaded.\n");
        return help ? 0 : 2;
    }

    std::unique_ptr<ur::Detector> det;
    try { det = std::make_unique<ur::Detector>(o); }
    catch (const ur::RegexError& e) { std::fprintf(stderr, "error: %s\n", e.what()); return 2; }

    std::vector<ur::Group> groups;
    if (pid) {
        bool denied = false, needsElev = false, fdenied = false;
        groups = ur::scanProcess(*det, pid, {}, denied, needsElev);
        if (denied) {
            std::fprintf(stderr, "error: cannot open pid %lu%s\n", (unsigned long)pid,
                         needsElev ? " (needs elevation: run as administrator)" : "");
            return 2;
        }
    } else {
        bool fdenied = false;
        groups = ur::scanPaths(*det, inputs, &fdenied);
        if (fdenied) std::fprintf(stderr, "note: some of that could not be read; try an elevated shell\n");
    }

    std::string text = ur::exportResults(groups, format);
    if (!outFile.empty()) {
        if (!writeTextFile(outFile, text)) { std::fprintf(stderr, "error: cannot write output file\n"); return 2; }
        std::printf("wrote %zu results to %S\n", ur::countFindings(groups), outFile.c_str());
    } else {
        std::fputs(text.c_str(), stdout);
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
    ID_WORKSPACE, ID_MONITOR, ID_MONITOR_INTERVAL, ID_SCAN_SETTINGS, ID_DASHBOARD
};
constexpr UINT WM_APP_DONE = WM_APP + 1;
constexpr UINT WM_APP_UPDATE_FOUND = WM_APP + 2;   // background check found a newer version
constexpr UINT WM_APP_UPDATE_PROGRESS = WM_APP + 3; // wParam = percent, download running
constexpr UINT WM_APP_UPDATE_DONE = WM_APP + 4;     // wParam: 1 = ready to relaunch, 0 = failed (lParam = wchar_t* msg)
constexpr UINT WM_APP_UPDATE_UPTODATE = WM_APP + 5; // manual check: nothing newer
constexpr UINT_PTR TIMER_PROGRESS = 1;
constexpr UINT_PTR TIMER_PROCS = 2;
constexpr UINT_PTR TIMER_MONITOR = 3;
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
HWND g_secDecode, g_ascii, g_utf16, g_b64, g_hex;
HWND g_scan, g_pause, g_cancel, g_monitor, g_monitorInterval, g_status;
HWND g_secResults, g_filter, g_results, g_copy, g_save, g_editor, g_clear, g_about;
HWND g_pagePrev, g_pageNext, g_pageLabel, g_workspace, g_dashboard;
HWND g_newOnly;
ur::ScanComparison g_comparison;
std::vector<ur::Group> g_newResults;
std::vector<ur::Group> g_previousComplete;
ur::SessionDelta g_liveDelta;
std::string g_scanContext;
bool g_hasComparison = false;
HFONT g_font = nullptr, g_fontHdr = nullptr, g_fontMono = nullptr;
int g_dpi = 96;
RECT g_segRect{};
RECT g_fields[4]{};
RECT g_listCard{};
int S(int v) { return MulDiv(v, g_dpi, 96); }
HBRUSH g_bgBrush = nullptr, g_bg2Brush = nullptr;

std::vector<fxchain::RipProcess> g_procsAll;   // full enumeration
std::vector<fxchain::RipProcess> g_procsView;  // what the combo currently shows
std::atomic<bool> g_cancelFlag{false};
ur::ScanGate g_scanGate;
std::atomic<bool> g_scanning{false};
std::atomic<long long> g_elapsedMs{0};
std::vector<ur::Group> g_lastResults;
std::vector<ur::Group> g_viewResults;
std::vector<ur::Group> g_pageResults;
std::size_t g_page = 0;
constexpr std::size_t kPageSize = 500;
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
ur::ScanProgress g_progress;
ur::FileSelection g_fileSelection;
std::string g_scanError;
std::thread g_scanThread;

/* auto-update state, all touched only on the UI thread except the worker
   below, which only PostMessages back. See update.hpp. */
std::filesystem::path appDataDir();
ur::UpdatePrefs g_updatePrefs;
ur::UpdateInfo g_update;
std::thread g_updateThread;
std::atomic<bool> g_updateBusy{false};
bool g_updateManual = false;                       // true while a user-triggered check runs
std::filesystem::path updatePrefsPath() { return appDataDir() / L"update.ini"; }
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

bool isMode(HWND h) { return h == g_modeUrl || h == g_modeRegex; }
bool isChip(HWND h) {
    for (HWND t : {g_ascii, g_utf16, g_b64, g_hex, g_pEmail, g_pIpv4, g_pIpv6, g_pGuid, g_pApi, g_pPath,
                   g_pDl, g_crap, g_newOnly})
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
    wchar_t t[256] = L"";
    SendMessageW(d->hwndItem, CB_GETLBTEXT, d->itemID, (LPARAM)t);
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

std::filesystem::path presetFilePath() {
    std::wstring p(32768, L'\0');
    DWORD n = GetModuleFileNameW(nullptr, p.data(), (DWORD)p.size());
    p.resize(n);
    return std::filesystem::path(p).parent_path() / L"regex-user-presets.ini";
}

void applyUserPreset(const ur::UserPreset& p) {
    g_applyingPreset = true;
    g_profileExtras.clear(); g_profileNames = {p.name};
    setChecked(g_ascii, p.ascii); setChecked(g_utf16, p.utf16);
    setChecked(g_hex, p.hex); setChecked(g_b64, p.base64);
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
    PE_ASCII, PE_UTF16, PE_HEX, PE_BASE64, PE_CUSTOM, PE_EMAIL, PE_IPV4, PE_IPV6,
    PE_GUID, PE_APIKEY, PE_FILEPATH, PE_DOWNLOAD, PE_SAMPLE, PE_TEST, PE_ADD_PROFILE,
    PE_POSITIVE, PE_NEGATIVE, PE_RUN_CASES, PE_T_PRESETS, PE_T_NAME, PE_T_DESC, PE_T_REGEX,
    PE_T_DECODERS, PE_T_MODES, PE_STATUS, PE_T_SAMPLE, PE_T_POSITIVE, PE_T_NEGATIVE
};

HWND g_pe = nullptr, g_peList, g_peName, g_peDesc, g_peRegex, g_peStatus;
HWND g_peAscii, g_peUtf16, g_peHex, g_peBase64, g_peCustom, g_peEmail, g_peIpv4, g_peIpv6;
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
    for (const auto& p : g_userPresets) SendMessageW(g_peList, LB_ADDSTRING, 0, (LPARAM)widen(p.name).c_str());
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
    p.hex = peCheck(g_peHex); p.base64 = peCheck(g_peBase64);
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
    peCheck(g_peHex, p.hex); peCheck(g_peBase64, p.base64);
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
        {PE_TEST, 14, 408 + a, 190, 28}, {PE_ADD_PROFILE, 14, 443 + a, 190, 28}, {PE_RUN_CASES, 14, 444 + b, 190, 28},
        {PE_T_NAME, 220, 12, w, 20}, {PE_NAME, 220, 34, w, 26},
        {PE_T_DESC, 220, 70, w, 20}, {PE_DESC, 220, 92, w, fd},
        {PE_T_REGEX, 220, 102 + fd, w, 20}, {PE_REGEX, 220, 124 + fd, w, fr},
        {PE_T_DECODERS, 220, 136 + a, w, 20}, {PE_ASCII, 220, 158 + a, 90, 24}, {PE_UTF16, 315, 158 + a, 90, 24},
        {PE_HEX, 410, 158 + a, 90, 24}, {PE_BASE64, 505, 158 + a, 100, 24},
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
                     {g_hex, p.hex}, {g_b64, p.base64}, {g_pEmail, p.email}, {g_pIpv4, p.ipv4},
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
    s += "Portable workspace storage uses SQLite.\r\n\r\n";
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
void selectPid(uint32_t pid) {
    for (int i = 0; i < (int)g_procsView.size(); ++i)
        if (g_procsView[i].pid == pid) { SendMessageW(g_source, CB_SETCURSEL, i, 0); return; }
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

/* poll: refresh the combo when the process set changes, and drop results whose
   process has exited. skipped while scanning or with the dropdown open. */
void autoRefreshProcs() {
    if (g_scanning) return;
    auto now = fxchain::ripBackend().enumerate();
    std::unordered_set<uint32_t> after;
    for (const auto& p : now) after.insert(p.pid);
    if (g_resultsPid && !after.count(g_resultsPid)) {
        clearResults();
        g_statusFull = L"The scanned process exited; results cleared.";
        SetWindowTextW(g_status, g_statusFull.c_str());
    }
    std::unordered_set<uint32_t> before;
    for (const auto& p : g_procsAll) before.insert(p.pid);
    if (before == after) return;
    if (SendMessageW(g_source, CB_GETDROPPEDSTATE, 0, 0)) return;
    uint32_t keep = selectedPid();
    g_procsAll = std::move(now);
    sortProcs();
    applyProcFilter();
    if (keep) selectPid(keep);
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
LRESULT CALLBACK resultsSub(HWND h, UINT msg, WPARAM wp, LPARAM lp, UINT_PTR, DWORD_PTR) {
    if (msg == WM_DROPFILES) { onDrop((HDROP)wp); return 0; }
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
    LRESULT res = DefSubclassProc(h, msg, wp, lp);
    if (msg != WM_PAINT) return res;

    RECT cr; GetClientRect(h, &cr);
    const int n = (int)g_pageResults.size();
    int lo = 0, hi = n - 1, first = n;
    while (lo <= hi) {
        int mid = (lo + hi) >> 1;
        RECT r{};
        ListView_GetGroupRect(h, mid, LVGGR_HEADER, &r);
        if (r.bottom > cr.top) { first = mid; hi = mid - 1; } else lo = mid + 1;
    }

    HDC dc = GetDC(h);
    RECT hr{};
    GetClientRect(ListView_GetHeader(h), &hr);
    HBRUSH rule = CreateSolidBrush(kCard);
    for (int c = 0, x = 0; c < 2; ++c) {
        x += ListView_GetColumnWidth(h, c);
        RECT rr{ x - 2, hr.bottom, x + 2, cr.bottom };
        FillRect(dc, &rr, rule);
    }
    DeleteObject(rule);
    HFONT of = (HFONT)SelectObject(dc, g_fontHdr);
    HPEN pen = CreatePen(PS_SOLID, 1, kBSub), op = (HPEN)SelectObject(dc, pen);
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, kAccent2);
    for (int i = first; i < n; ++i) {
        RECT gr{};
        ListView_GetGroupRect(h, i, LVGGR_HEADER, &gr);
        if (gr.top >= cr.bottom) break;
        const ur::Group& g = g_pageResults[i];
        FillRect(dc, &gr, g_bgBrush);
        MoveToEx(dc, gr.left, gr.bottom - 1, nullptr);
        LineTo(dc, gr.right, gr.bottom - 1);

        std::wstring t = widen(g.name);
        RECT tr = gr; tr.left += S(12);
        HFONT om = (HFONT)SelectObject(dc, g_fontMono);
        SIZE sz{};
        GetTextExtentPoint32W(dc, t.c_str(), (int)t.size(), &sz);
        SetTextColor(dc, kText);
        DrawTextW(dc, t.c_str(), -1, &tr, DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);
        SelectObject(dc, om);

        std::wstring cnt = std::to_wstring(g.items.size());
        SIZE cs{};
        HFONT ou = (HFONT)SelectObject(dc, g_font);
        GetTextExtentPoint32W(dc, cnt.c_str(), (int)cnt.size(), &cs);
        SelectObject(dc, ou);
        const int ch = S(20);
        RECT chip{ tr.left + sz.cx + S(10), (gr.top + gr.bottom - ch) / 2, 0, 0 };
        chip.right = chip.left + cs.cx + S(14);
        chip.bottom = chip.top + ch;
        if (chip.right < gr.right - S(8)) {
            roundRect(dc, chip, ch, kBg, kBDef);
            inkText(dc, cnt.c_str(), chip, g_font, kText2, DT_SINGLELINE | DT_CENTER | DT_VCENTER);
        }
    }
    SelectObject(dc, op); DeleteObject(pen);
    SelectObject(dc, of);

    ReleaseDC(h, dc);
    return res;
}

ur::Options gatherOptions() {
    ur::Options o;
    o.ascii = isChecked(g_ascii);
    o.utf16 = isChecked(g_utf16);
    o.base64 = isChecked(g_b64);
    o.hex = isChecked(g_hex);
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
                   g_customLabel, g_custom, g_presets})
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
    g_viewResults.clear();
    g_pageResults.clear(); g_page = 0;
    g_resultsPid = 0;
    ListView_DeleteAllItems(g_results);
    ListView_RemoveAllGroups(g_results);
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

void populateResults(const std::vector<ur::Group>& groups) {
    const auto total = ur::countFindings(groups);
    const auto pages = std::max<std::size_t>(1, (total + kPageSize - 1) / kPageSize);
    if (g_page >= pages) g_page = pages - 1;
    const auto begin = g_page * kPageSize, end = std::min(total, begin + kPageSize);
    g_pageResults.clear();
    std::size_t at = 0;
    for (const auto& g : groups) {
        ur::Group pageGroup{g.name, {}};
        for (const auto& f : g.items) {
            if (at >= begin && at < end) pageGroup.items.push_back(f);
            ++at;
        }
        if (!pageGroup.items.empty()) g_pageResults.push_back(std::move(pageGroup));
    }
    EnableWindow(g_pagePrev, g_page > 0);
    EnableWindow(g_pageNext, g_page + 1 < pages);
    SetWindowTextW(g_pageLabel, (std::to_wstring(g_page + 1) + L" / " + std::to_wstring(pages)).c_str());
    ListView_DeleteAllItems(g_results);
    ListView_RemoveAllGroups(g_results);
    ListView_EnableGroupView(g_results, TRUE);
    int item = 0, gid = 0;
    for (const auto& g : g_pageResults) {
        /* empty default header: we owner-paint name + count in resultsSub, so the
           listview must draw nothing here or the two renders ghost each other. */
        wchar_t blank[] = L"";
        LVGROUP lg{};
        lg.cbSize = sizeof(lg);
        lg.mask = LVGF_HEADER | LVGF_GROUPID;
        lg.pszHeader = blank;
        lg.iGroupId = gid;
        ListView_InsertGroup(g_results, -1, &lg);
        for (const auto& f : g.items) {
            std::wstring v = widen(f.value);
            LVITEMW it{};
            it.mask = LVIF_TEXT | LVIF_GROUPID;
            it.iItem = item;
            it.pszText = v.data();
            it.iGroupId = gid;
            int idx = ListView_InsertItem(g_results, &it);
            std::wstring enc = widen(ur::encName(f.enc));
            ListView_SetItemText(g_results, idx, 1, enc.data());
            std::wstring src = widen(f.source);
            ListView_SetItemText(g_results, idx, 2, src.data());
            if (f.hasOffset) {
                wchar_t addr[32];
                _snwprintf_s(addr, _TRUNCATE, L"0x%llX", (unsigned long long)f.offset);
                ListView_SetItemText(g_results, idx, 3, addr);
            }
            ++item;
        }
        ++gid;
    }
    fitColumns();
}

void applyResultFilter() {
    g_page = 0;
    wchar_t q[256] = L"";
    GetWindowTextW(g_filter, q, 256);
    std::string query = lower(narrow(q));
    g_viewResults.clear();
    const auto& visible = isChecked(g_newOnly) && g_hasComparison ? g_newResults : g_lastResults;
    for (const auto& g : visible) {
        if (query.empty() || lower(g.name).find(query) != std::string::npos) { g_viewResults.push_back(g); continue; }
        ur::Group hit;
        hit.name = g.name;
        for (const auto& f : g.items)
            if (lower(f.value).find(query) != std::string::npos ||
                lower(f.source).find(query) != std::string::npos ||
                lower(ur::encName(f.enc)).find(query) != std::string::npos)
                hit.items.push_back(f);
        if (!hit.items.empty()) g_viewResults.push_back(std::move(hit));
    }
    populateResults(g_viewResults);
    enableResultActions(!g_viewResults.empty());
    if (query.empty() && !isChecked(g_newOnly)) { SetWindowTextW(g_status, g_statusFull.c_str()); return; }
    wchar_t msg[128];
    _snwprintf_s(msg, _TRUNCATE, L"%zu of %zu results   (%s)",
                 ur::countFindings(g_viewResults), ur::countFindings(g_lastResults),
                 isChecked(g_newOnly) ? L"new since previous complete scan" : L"filtered");
    SetWindowTextW(g_status, msg);
}

void onDone(std::vector<ur::Group>* groups) {
    if (g_scanThread.joinable()) g_scanThread.join();
    KillTimer(g_main, TIMER_PROGRESS);
    g_lastResults = std::move(*groups);
    delete groups;
    const bool complete = !g_cancelFlag && g_scanError.empty() && !g_scanDenied &&
                          !g_scanDeniedFiles && !g_progress.skipped;
    g_hasComparison = complete && g_comparison.matches(g_scanContext);
    g_newResults = g_hasComparison ? g_comparison.added(g_lastResults) : std::vector<ur::Group>{};
    g_liveDelta = g_hasComparison ? ur::compareSessions(g_previousComplete, g_lastResults) : ur::SessionDelta{};
    if (complete) { g_comparison.remember(g_scanContext, g_lastResults); g_previousComplete = g_lastResults; }
    if (!g_hasComparison) setChecked(g_newOnly, false);
    EnableWindow(g_newOnly, g_hasComparison);
    g_resultsPid = (g_scanPid && !g_scanDenied) ? g_scanPid : 0;
    wchar_t msg[256];
    _snwprintf_s(msg, _TRUNCATE, L"%zu results in %zu groups, sorted Z to A   (%.2f s)%s",
                 ur::countFindings(g_lastResults), g_lastResults.size(),
                 g_elapsedMs.load() / 1000.0, g_cancelFlag ? L"  (cancelled)" : L"");
    g_statusFull = msg;
    if (!g_scanError.empty()) g_statusFull = L"Scan failed: " + widen(g_scanError);
    else if (!g_cancelFlag && !g_scanDenied && !g_scanDeniedFiles && !g_progress.skipped)
        g_statusFull = L"100.0% - " + g_statusFull;
    if (g_progress.skipped)
        g_statusFull += L" - " + std::to_wstring(g_progress.skipped.load()) + L" bytes unreadable/changed";
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

void setRegexMode() {
    setChecked(g_modeUrl, false);
    setChecked(g_modeRegex, true);
    updateModeVisibility();
    relayout(g_main);
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
    std::vector<std::filesystem::path> paths = g_chosenPaths;
    if (paths.empty()) {
        int sel = (int)SendMessageW(g_source, CB_GETCURSEL, 0, 0);
        if (sel >= 0 && sel < (int)g_procsView.size()) pid = g_procsView[sel].pid;
    }
    if (!pid && paths.empty()) {
        MessageBoxW(g_main, L"Choose a process, or drop files on the window.", L"StringRipper", MB_ICONINFORMATION);
        return;
    }

    g_cancelFlag = false;
    g_scanGate.setPaused(false);
    std::string source = "pid:" + std::to_string(pid);
    if (!paths.empty()) {
        std::vector<std::string> names;
        for (const auto& p : paths)
            names.push_back(narrow(std::filesystem::absolute(p).lexically_normal().wstring().c_str()));
        std::sort(names.begin(), names.end());
        source = "files:";
        for (const auto& n : names) source += std::to_string(n.size()) + ":" + n;
    }
    g_scanContext = ur::comparisonContext(source, o) + ur::selectionContext(g_fileSelection);
    g_scanPid = pid;
    g_progress.reset();
    g_scanError.clear();
    setScanningUi(true);
    SetWindowTextW(g_filter, L"");
    SetWindowTextW(g_status, L"Preparing scan...");
    SetTimer(g_main, TIMER_PROGRESS, 120, nullptr);

    const auto selection = g_fileSelection;
    g_scanThread = std::thread([detector, pid, paths, selection]() {
        auto* result = new std::vector<ur::Group>();
        bool denied = false, needsElev = false, fdenied = false;
        auto t0 = std::chrono::steady_clock::now();
        try {
            auto cancel = [] { return g_cancelFlag.load(); };
            auto pause = [cancel] { g_scanGate.wait(cancel); };
            ur::DriverLimits limits;
            limits.rangeStart = selection.rangeStart; limits.rangeEnd = selection.rangeEnd;
            if (pid) *result = ur::scanProcess(*detector, pid, cancel, denied, needsElev, &g_progress, limits, pause);
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

std::filesystem::path appDataDir() {
    wchar_t base[32768]{};
    DWORD n = GetEnvironmentVariableW(L"LOCALAPPDATA", base, 32768);
    std::filesystem::path dir;
    if (n && n < 32768) dir = std::filesystem::path(base) / L"StringRipper";
    else {
        wchar_t exe[MAX_PATH]{}; GetModuleFileNameW(nullptr, exe, MAX_PATH);
        dir = std::filesystem::path(exe).parent_path();
    }
    std::filesystem::create_directories(dir);
    return dir;
}
std::filesystem::path workspaceDatabase() { return appDataDir() / L"workspace.sqlite"; }
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
    setChecked(g_b64, o.base64); setChecked(g_hex, o.hex);
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
                ur::SessionStore db(workspaceDatabase());
                db.saveSession({0, name, source, "", g_lastResults}); wsRefresh();
            } else if (id == WS_OPEN_SESSION) {
                auto selected = wsSelectedSessions();
                if (selected.size() != 1) throw std::runtime_error("Select exactly one session to open");
                ur::SessionStore db(workspaceDatabase());
                auto session = db.loadSession(g_wsIndex[selected[0]].id);
                g_lastResults = std::move(session.groups);
                g_resultsPid = 0;
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
                    if (sel >= 0 && sel < (int)g_procsView.size()) job.pid = g_procsView[sel].pid;
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
                if (job->pid) { g_chosenPaths.clear(); selectPid(job->pid); }
                else setSourcePaths(job->sources);
                DestroyWindow(h);
                PostMessageW(g_main, WM_COMMAND, ID_SCAN, 0);
            } else if (id == WS_ADD_FAVORITE) {
                ur::SessionStore db(workspaceDatabase());
                if (!g_chosenPaths.empty()) {
                    for (const auto& path : g_chosenPaths) db.setFavorite("path", path.string(), true);
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
                    auto it = std::find_if(g_procsAll.begin(), g_procsAll.end(),
                        [&](const fxchain::RipProcess& p) { return p.name == target; });
                    if (it == g_procsAll.end()) throw std::runtime_error("Favorite process is not running");
                    g_chosenPaths.clear(); selectPid(it->pid);
                    DestroyWindow(h);
                } else {
                    auto path = std::filesystem::u8path(target);
                    if (!std::filesystem::exists(path)) throw std::runtime_error("Favorite path no longer exists");
                    setSourcePaths({path});
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
        auto summary = widen(ur::dashboardText(ur::summarizeResults(g_viewResults)));
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
    if (row < 0) return nullptr;
    for (const auto& g : g_pageResults) {
        if (row < (int)g.items.size()) return &g.items[row];
        row -= (int)g.items.size();
    }
    return nullptr;
}
void showFindingDetails(const ur::Finding& f) {
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
HWND g_inspector = nullptr;
std::wstring g_inspectorText;
LRESULT CALLBACK InspectorProc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        darkTitle(h);
        peCtl(h, L"STATIC", L"Read-only bytes around the selected finding", 0, 0, 14, 12, 700, 24);
        HWND view = peCtl(h, L"EDIT", g_inspectorText.c_str(), 0,
            ES_MULTILINE | ES_READONLY | WS_BORDER | WS_VSCROLL | WS_HSCROLL,
            14, 42, 750, 320);
        SendMessageW(view, WM_SETFONT, (WPARAM)g_fontMono, TRUE);
        peCtl(h, L"BUTTON", L"Close", IDCANCEL, BS_DEFPUSHBUTTON, 654, 374, 110, 30);
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
    case WM_DESTROY: g_inspector = nullptr; EnableWindow(g_main, TRUE); SetForegroundWindow(g_main); return 0;
    }
    return DefWindowProcW(h, msg, wp, lp);
}
void showOffsetInspector(std::wstring text) {
    g_inspectorText = std::move(text);
    WNDCLASSEXW wc{sizeof(wc)}; wc.lpfnWndProc = InspectorProc;
    wc.hInstance = GetModuleHandleW(nullptr); wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = g_bgBrush; wc.lpszClassName = L"StringRipperOffsetInspector";
    RegisterClassExW(&wc);
    RECT r{0, 0, S(778), S(415)};
    AdjustWindowRectEx(&r, WS_CAPTION | WS_SYSMENU, FALSE, WS_EX_DLGMODALFRAME);
    EnableWindow(g_main, FALSE);
    g_inspector = CreateWindowExW(WS_EX_DLGMODALFRAME, wc.lpszClassName, L"Offset inspector",
        WS_CAPTION | WS_SYSMENU, CW_USEDEFAULT, CW_USEDEFAULT, r.right-r.left, r.bottom-r.top,
        g_main, nullptr, wc.hInstance, nullptr);
    if (!g_inspector) { EnableWindow(g_main, TRUE); return; }
    ShowWindow(g_inspector, SW_SHOW); UpdateWindow(g_inspector);
}
void inspectOffset(const ur::Finding& f, bool file) {
    if (!f.hasOffset) return;
    constexpr std::size_t kPreview = 256;
    std::vector<uint8_t> bytes(kPreview);
    uint64_t start = file && f.offset > 64 ? f.offset - 64 : f.offset;
    std::size_t got = 0;
    if (file) {
        std::ifstream input(std::filesystem::u8path(f.source), std::ios::binary);
        if (input) {
            input.seekg(static_cast<std::streamoff>(start));
            input.read(reinterpret_cast<char*>(bytes.data()), bytes.size());
            got = static_cast<std::size_t>(input.gcount());
        }
    } else if (g_resultsPid) {
        fxchain::RipStats stats; fxchain::RipTargetInfo info;
        fxchain::ripBackend().withReader(g_resultsPid, stats, info, [&](fxchain::IMemoryReader& reader) {
            auto result = reader.read(start, bytes.data(), bytes.size());
            got = result.bytesRead;
        });
    }
    if (!got) {
        MessageBoxW(g_main, L"Source bytes are no longer readable.", L"Offset inspector", MB_ICONWARNING);
        return;
    }
    std::wstring preview = L"Selected offset/address: 0x";
    wchar_t address[32]; _snwprintf_s(address, _TRUNCATE, L"%llX\r\n\r\n", (unsigned long long)f.offset);
    preview += address;
    for (std::size_t i = 0; i < got; i += 16) {
        wchar_t line[256];
        _snwprintf_s(line, _TRUNCATE, L"%012llX  ", (unsigned long long)(start + i));
        preview += line;
        for (std::size_t j = 0; j < 16; ++j) {
            if (i + j < got) {
                wchar_t b[8]; _snwprintf_s(b, _TRUNCATE, L"%02X ", unsigned(bytes[i + j]));
                preview += b;
            } else preview += L"   ";
        }
        preview += L" |";
        for (std::size_t j = 0; j < 16 && i + j < got; ++j)
            preview += (bytes[i + j] >= 32 && bytes[i + j] <= 126) ? wchar_t(bytes[i + j]) : L'.';
        preview += L"|\r\n";
    }
    showOffsetInspector(std::move(preview));
}
void showFindingMenu(const ur::Finding& f) {
    HMENU menu = CreatePopupMenu();
    AppendMenuW(menu, MF_STRING, 1, L"Details and context");
    std::error_code ec;
    bool file = std::filesystem::is_regular_file(std::filesystem::u8path(f.source), ec);
    if (file) AppendMenuW(menu, MF_STRING, 2, L"Open source file");
    if (f.hasOffset && (file || g_resultsPid)) AppendMenuW(menu, MF_STRING, 4, L"Inspect bytes at offset");
    AppendMenuW(menu, MF_STRING, 3, L"Favorite source");
    POINT p; GetCursorPos(&p);
    int chosen = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, p.x, p.y, 0, g_main, nullptr);
    DestroyMenu(menu);
    if (chosen == 1) showFindingDetails(f);
    else if (chosen == 2 && file) ShellExecuteW(g_main, L"open", std::filesystem::u8path(f.source).c_str(), nullptr, nullptr, SW_SHOWNORMAL);
    else if (chosen == 4) inspectOffset(f, file);
    else if (chosen == 3) {
        try { ur::SessionStore db(workspaceDatabase()); db.setFavorite("source", f.source, true);
              SetWindowTextW(g_status, L"Source added to favorites"); }
        catch (const std::exception& e) { MessageBoxW(g_main, widen(e.what()).c_str(), L"Favorite", MB_ICONERROR); }
    }
}

void copySelected() {
    std::string text;
    int i = -1;
    while ((i = ListView_GetNextItem(g_results, i, LVNI_SELECTED)) != -1) {
        wchar_t buf[4096];
        ListView_GetItemText(g_results, i, 0, buf, 4096);
        text += narrow(buf);
        text += "\r\n";
    }
    if (text.empty()) return;
    if (!OpenClipboard(g_main)) return;
    EmptyClipboard();
    std::wstring w = widen(text);
    HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, (w.size() + 1) * sizeof(wchar_t));
    if (h) {
        memcpy(GlobalLock(h), w.c_str(), (w.size() + 1) * sizeof(wchar_t));
        GlobalUnlock(h);
        SetClipboardData(CF_UNICODETEXT, h);
    }
    CloseClipboard();
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
                auto id = db.saveSession({0, "Filtered export", "GUI results", "", g_viewResults});
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
        if (!writeTextFile(path.wstring(), ur::exportResults(g_viewResults, format)))
            MessageBoxW(g_main, L"Could not write the file.", L"StringRipper", MB_ICONERROR);
    }
}

void sendToEditor() {
    if (g_viewResults.empty()) return;
    wchar_t tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    std::wstring p = std::wstring(tmp) + L"StringRipper-" + std::to_wstring(GetTickCount64()) + L".txt";
    if (!writeTextFile(p, resultsToText(g_viewResults, g_lastMode))) {
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
    MoveWindow(g_source, m + S(6), y + S(4), cw - m * 2 - S(12), S(360), TRUE);   // 360 = dropdown height
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
    int pw = textW(g_presets, g_font) + S(26);
    g_fields[2].right = right - pw - sp;
    MoveWindow(g_presets, right - pw, cy, pw, rh, TRUE);
    MoveWindow(g_custom, m + lw + sp + S(6), cy + S(4),
               right - pw - sp - m - lw - sp - S(12), rh - S(8), TRUE);
    y = regex ? (cy + rh + gap) : (dy + rh + gap);

    // DECODE
    MoveWindow(g_secDecode, m, y, S(200), hh, TRUE); y += hh + hg;
    flow({g_ascii, g_utf16, g_b64, g_hex}, m, y, S(24));
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
    int ww = textW(g_workspace, g_font) + S(26);
    int dw = textW(g_dashboard, g_font) + S(26);
    MoveWindow(g_newOnly, right - nw, y, nw, rh, TRUE);
    MoveWindow(g_workspace, right - nw - sp - ww, y, ww, rh, TRUE);
    MoveWindow(g_dashboard, right - nw - sp - ww - sp - dw, y, dw, rh, TRUE);
    g_fields[3].right = right - nw - sp - ww - sp - dw - sp;
    MoveWindow(g_filter, m + sw + sp + S(6), y + S(4),
        g_fields[3].right - m - sw - sp - S(12), rh - S(8), TRUE);
    y += rh + hg;

    int bottom = ch - m - rh;
    int listH = (bottom - gap) - y;
    if (listH < S(60)) listH = S(60);
    g_listCard = { m, y, right, y + listH };
    MoveWindow(g_results, m + S(7), y + S(7), cw - m * 2 - S(14), listH - S(14), TRUE);
    fitColumns();

    flow({g_copy, g_save, g_editor, g_clear}, m, bottom, S(26));
    int aw = textW(g_about, g_font) + S(26);
    MoveWindow(g_pageNext, right - aw - S(84), bottom, S(78), rh, TRUE);
    MoveWindow(g_pagePrev, right - aw - S(170), bottom, S(78), rh, TRUE);
    MoveWindow(g_pageLabel, right - aw - S(245), bottom + S(7), S(70), lh, TRUE);
    MoveWindow(g_about, right - aw, bottom, aw, rh, TRUE);

}

void fitColumns() {
    RECT lc; GetClientRect(g_results, &lc);
    int encW = S(90), srcW = S(220), offW = S(115), valW = lc.right - encW - srcW - offW;
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
    if (!ur::httpGet(kUpdateManifestUrl, json, &err, 1 << 20, updateUserAgent())) {
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
                     updateProgress)) {
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
    g_updateThread = std::thread([manual]{ runUpdateCheck(manual); g_updateBusy = false; });
}
void startUpdateDownload() {
    bool expected = false;
    if (!g_updateBusy.compare_exchange_strong(expected, true)) return;
    if (g_updateThread.joinable()) g_updateThread.join();
    g_updateThread = std::thread([]{ runUpdateDownload(); g_updateBusy = false; });
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
        g_presets = mkPush(hwnd, L"User presets...", ID_PRESETS);

        g_secDecode = mkSection(hwnd, L"DECODE");
        g_ascii = mkChip(hwnd, L"ASCII", ID_ENC_ASCII);
        g_utf16 = mkChip(hwnd, L"UTF-16", ID_ENC_UTF16);
        g_b64 = mkChip(hwnd, L"Base64", ID_ENC_B64);
        g_hex = mkChip(hwnd, L"Hex", ID_ENC_HEX);
        for (HWND h : {g_ascii, g_utf16, g_b64, g_hex}) setChecked(h, true);

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
        g_workspace = mkPush(hwnd, L"Workspace...", ID_WORKSPACE);
        g_dashboard = mkPush(hwnd, L"Dashboard", ID_DASHBOARD);
        setChecked(g_newOnly, false); EnableWindow(g_newOnly, FALSE);
        g_results = CreateWindowExW(0, WC_LISTVIEWW, L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SHOWSELALWAYS,
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
        EnableWindow(g_pagePrev, FALSE); EnableWindow(g_pageNext, FALSE);
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
                applyUserPreset(g_userPresets.front());
                if (recovered) SetWindowTextW(g_status, L"Preset file was invalid; loaded the .bak copy.");
            } else if (!e.empty())
                SetWindowTextW(g_status, widen(std::string("Preset file: ") + e).c_str());
        }
        SetTimer(hwnd, TIMER_PROCS, 2000, nullptr);
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
        for (int i = 0; i < 4; ++i) {
            if (i == 2 && !IsWindowVisible(g_custom)) continue;
            roundRect(dc, g_fields[i], S(20), kBg2, kBSub);
        }
        roundRect(dc, g_listCard, S(26), kCard, kBSub);
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
        case ID_SEARCH: if (HIWORD(wp) == EN_CHANGE) applyProcFilter(); break;
        case ID_FILTER: if (HIWORD(wp) == EN_CHANGE) applyResultFilter(); break;
        case ID_REFRESH: refreshProcesses(); break;
        case ID_FILE: pickFile(); break;
        case ID_SCAN_SETTINGS: showScanSettings(); break;
        case ID_PRESETS: showPresetEditor(); break;
        case ID_WORKSPACE: showWorkspace(); break;
        case ID_DASHBOARD: showDashboard(); break;
        case ID_MODE_URL: case ID_MODE_REGEX: {
            bool url = LOWORD(wp) == ID_MODE_URL;
            setChecked(g_modeUrl, url);
            setChecked(g_modeRegex, !url);
            updateModeVisibility(); relayout(hwnd);
            break;
        }
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
        case ID_PAGE_PREV: if (g_page) { --g_page; populateResults(g_viewResults); } break;
        case ID_PAGE_NEXT: ++g_page; populateResults(g_viewResults); break;
        case ID_NEW_ONLY:
            setChecked(g_newOnly, !isChecked(g_newOnly)); applyResultFilter(); break;
        case ID_ENC_ASCII: case ID_ENC_UTF16: case ID_ENC_B64: case ID_ENC_HEX:
        case ID_P_EMAIL: case ID_P_IPV4: case ID_P_IPV6:
        case ID_P_GUID: case ID_P_APIKEY: case ID_P_PATH: case ID_P_DL: case ID_CRAP: {
            HWND c = (HWND)lp;
            setChecked(c, !isChecked(c));
            if (!g_applyingPreset) g_activePreset.clear();
            break;
        }
        case ID_CUSTOM:
            if (HIWORD(wp) == EN_CHANGE) {
                if (!g_applyingPreset) g_activePreset.clear();
                if (GetWindowTextLengthW(g_custom) > 0) setRegexMode();
            }
            break;
        case ID_SOURCE:
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
        if (!cds || cds->dwData != kDropMagic || cds->cbData < sizeof(wchar_t)) break;
        const wchar_t* p = (const wchar_t*)cds->lpData;
        std::vector<std::filesystem::path> paths;
        while (*p) { paths.emplace_back(p); p += wcslen(p) + 1; }
        if (!paths.empty() && !g_scanning) {
            setSourcePaths(std::move(paths));
            SetForegroundWindow(hwnd);
            PostMessageW(hwnd, WM_COMMAND, ID_SCAN, 0);
        }
        return TRUE;
    }
    case WM_NOTIFY: {
        auto* hdr = (NMHDR*)lp;
        if (hdr->idFrom == ID_RESULTS && (hdr->code == NM_DBLCLK || hdr->code == NM_RCLICK)) {
            auto* action = (NMITEMACTIVATE*)lp;
            if (const auto* f = findingAtRow(action->iItem)) {
                if (hdr->code == NM_DBLCLK) showFindingDetails(*f);
                else showFindingMenu(*f);
            }
            return 0;
        }
        auto* cd = (NMLVCUSTOMDRAW*)lp;
        if (cd->nmcd.hdr.idFrom != ID_RESULTS || cd->nmcd.hdr.code != NM_CUSTOMDRAW) break;
        if (cd->nmcd.dwDrawStage == CDDS_PREPAINT) return CDRF_NOTIFYITEMDRAW;
        if (cd->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) return CDRF_NOTIFYSUBITEMDRAW;
        if (cd->nmcd.dwDrawStage == (CDDS_ITEMPREPAINT | CDDS_SUBITEM)) {
            if (cd->iSubItem == 0) { SelectObject(cd->nmcd.hdc, g_fontMono); return CDRF_NEWFONT; }
            if (cd->iSubItem == 1) {
                HWND lv = cd->nmcd.hdr.hwndFrom;
                const int row = (int)cd->nmcd.dwItemSpec;
                wchar_t t[32] = L"";
                ListView_GetItemText(lv, row, 1, t, 32);
                RECT r{};
                ListView_GetSubItemRect(lv, row, 1, LVIR_BOUNDS, &r);
                HDC hdc = cd->nmcd.hdc;
                HBRUSH b = CreateSolidBrush(kCard);
                FillRect(hdc, &r, b);
                DeleteObject(b);
                if (!t[0]) return CDRF_SKIPDEFAULT;
                HFONT of = (HFONT)SelectObject(hdc, g_font);
                SIZE sz{};
                GetTextExtentPoint32W(hdc, t, (int)wcslen(t), &sz);
                SelectObject(hdc, of);
                const int ch = S(20);
                RECT chip{ r.left + S(6), (r.top + r.bottom - ch) / 2, 0, 0 };
                chip.right = chip.left + sz.cx + S(14);
                chip.bottom = chip.top + ch;
                roundRect(hdc, chip, S(12), kBg3, kBg3);
                inkText(hdc, t, chip, g_font, kText2, DT_SINGLELINE | DT_CENTER | DT_VCENTER);
                return CDRF_SKIPDEFAULT;
            }
            if (cd->iSubItem == 2) {
                SelectObject(cd->nmcd.hdc, g_fontMono);
                cd->clrText = kText3;
                return CDRF_NEWFONT;
            }
        }
        return CDRF_DODEFAULT;
    }
    case WM_APP_DONE:
        onDone((std::vector<ur::Group>*)lp);
        return 0;
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
            if (ur::selfReplaceAndRelaunch(g_updateDownloadPath, &err)) {
                DestroyWindow(hwnd);   // new instance is already launching
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
        g_cancelFlag = true;
        g_scanGate.setPaused(false);
        if (g_scanThread.joinable()) g_scanThread.join();
        if (g_updateThread.joinable()) g_updateThread.join();
        { MSG pending{};
          while (PeekMessageW(&pending, hwnd, WM_APP_UPDATE_DONE, WM_APP_UPDATE_DONE, PM_REMOVE))
              if (pending.wParam == 0) free((wchar_t*)pending.lParam); }
        { MSG pending{};
          while (PeekMessageW(&pending, hwnd, WM_APP_DONE, WM_APP_DONE, PM_REMOVE))
              delete (std::vector<ur::Group>*)pending.lParam; }
        KillTimer(hwnd, TIMER_PROGRESS);
        KillTimer(hwnd, TIMER_PROCS);
        KillTimer(hwnd, TIMER_MONITOR);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

int runGui(HINSTANCE hInst) {
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
    if (mtx && GetLastError() == ERROR_ALREADY_EXISTS) {
        HWND ex = FindWindowW(L"StringRipperWindow", nullptr);
        if (ex) {
            if (IsIconic(ex)) ShowWindow(ex, SW_RESTORE);
            SetForegroundWindow(ex);
            if (!g_autoRipPaths.empty()) forwardPaths(ex, g_autoRipPaths);
        }
        return 0;
    }
    return runGui(hInst);
}
