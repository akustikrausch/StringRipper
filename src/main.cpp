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
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "scan_core.hpp"
#include "scan_driver.hpp"
#include "file_read.hpp"
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
#pragma comment(linker, "/MANIFESTUAC:\"level='asInvoker' uiAccess='false'\"")
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
    std::string s(static_cast<std::size_t>(n - 1), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), n, nullptr, nullptr);
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

static constexpr std::size_t kMaxInFlight = 256u * 1024 * 1024;

static bool elevated() {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return false;
    TOKEN_ELEVATION e{};
    DWORD n = 0;
    bool up = GetTokenInformation(tok, TokenElevation, &e, sizeof(e), &n) && e.TokenIsElevated;
    CloseHandle(tok);
    return up;
}

static bool relaunchElevated(const std::wstring& args) {
    wchar_t exe[MAX_PATH] = L"";
    GetModuleFileNameW(nullptr, exe, MAX_PATH);
    SHELLEXECUTEINFOW si{ sizeof(si) };
    si.lpVerb = L"runas";
    si.lpFile = exe;
    si.lpParameters = args.empty() ? nullptr : args.c_str();
    si.nShow = SW_SHOWNORMAL;
    return ShellExecuteExW(&si) != FALSE;
}

// ---------------------------------------------------------------- scan helpers (shared GUI/CLI)

static std::vector<ur::Group> scanProcess(const ur::Detector& det, uint32_t pid,
                                          const std::function<bool()>& cancel,
                                          bool& accessDenied, bool& needsElevation) {
    accessDenied = false; needsElevation = false;
    std::string pname = fxchain::ripBackend().processName(pid);
    if (pname.empty()) pname = "pid" + std::to_string(pid);
    ur::DriverLimits lim;
    ur::ScanPool pool(det, 0, kMaxInFlight);
    fxchain::RipStats stats;
    fxchain::RipTargetInfo info;
    bool opened = fxchain::ripBackend().withReader(pid, stats, info,
        [&](fxchain::IMemoryReader& rd) {
            ur::scanReaderInto(rd, pool, pname, lim,
                               [&](uint64_t) { return !(cancel && cancel()); });
        });
    auto groups = pool.finish();
    if (!opened) {
        accessDenied = true;
        needsElevation = (stats.access == fxchain::RipAccess::NeedsElevation);
    }
    return groups;
}

static std::vector<ur::Group> scanPaths(const ur::Detector& det,
                                        const std::vector<std::filesystem::path>& inputs,
                                        bool* denied = nullptr) {
    ur::DriverLimits lim;
    ur::ScanPool pool(det, 0, kMaxInFlight);
    auto files = ur::expandInputs(inputs);
    std::size_t bad = 0;
    for (const auto& f : files)
        if (!ur::scanFileInto(f, pool, lim)) ++bad;
    if (denied) *denied = bad > 0 || (files.empty() && !inputs.empty());
    return pool.finish();
}

// ---------------------------------------------------------------- CLI

static int runCli(int argc, wchar_t** argv) {
    ur::Options o;
    std::vector<std::filesystem::path> inputs;
    uint32_t pid = 0;
    std::wstring outFile;
    bool help = false;

    auto next = [&](int& i) -> std::wstring { return (i + 1 < argc) ? argv[++i] : std::wstring(); };
    for (int i = 1; i < argc; ++i) {
        std::wstring a = argv[i];
        if (a == L"--help" || a == L"-h" || a == L"/?") help = true;
        else if (a == L"--cli") {}
        else if (a == L"--file" || a == L"--folder") inputs.push_back(next(i));
        else if (a == L"--pid") pid = (uint32_t)std::wcstoul(next(i).c_str(), nullptr, 10);
        else if (a == L"--regex") { o.mode = ur::Mode::Regex; o.customRegex = narrow(next(i).c_str()); }
        else if (a == L"--preset") { o.mode = ur::Mode::Regex; o.presets = splitCsv(narrow(next(i).c_str())); }
        else if (a == L"--scheme") o.schemes = splitCsv(narrow(next(i).c_str()));
        else if (a == L"--icase") o.caseInsensitive = true;
        else if (a == L"--no-ascii") o.ascii = false;
        else if (a == L"--no-utf16") o.utf16 = false;
        else if (a == L"--no-base64") o.base64 = false;
        else if (a == L"--no-hex") o.hex = false;
        else if (a == L"--out") outFile = next(i);
    }

    if (::AttachConsole(ATTACH_PARENT_PROCESS)) {
        FILE* f = nullptr;
        freopen_s(&f, "CONOUT$", "w", stdout);
        freopen_s(&f, "CONOUT$", "w", stderr);
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
        groups = scanProcess(*det, pid, {}, denied, needsElev);
        if (denied) {
            std::fprintf(stderr, "error: cannot open pid %lu%s\n", (unsigned long)pid,
                         needsElev ? " (needs elevation: run as administrator)" : "");
            return 2;
        }
    } else {
        bool fdenied = false;
        groups = scanPaths(*det, inputs, &fdenied);
        if (fdenied) std::fprintf(stderr, "note: some of that could not be read; try an elevated shell\n");
    }

    std::string text = resultsToText(groups, o.mode);
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
    ID_CUSTOM, ID_SCAN, ID_CANCEL, ID_RESULTS, ID_COPY, ID_SAVE, ID_EDITOR, ID_ABOUT, ID_FILTER, ID_ADMIN
};
constexpr UINT WM_APP_DONE = WM_APP + 1;

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
HWND g_secSource, g_search, g_source, g_refresh, g_file, g_admin, g_srcInfo;
HWND g_secFind, g_modeUrl, g_modeRegex, g_urlHint;
HWND g_presetLabel, g_pEmail, g_pIpv4, g_pIpv6, g_pGuid, g_pApi, g_pPath, g_customLabel, g_custom;
HWND g_secDecode, g_ascii, g_utf16, g_b64, g_hex;
HWND g_scan, g_cancel, g_status;
HWND g_secResults, g_filter, g_results, g_copy, g_save, g_editor, g_about;
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
std::atomic<bool> g_scanning{false};
std::atomic<long long> g_elapsedMs{0};
std::vector<ur::Group> g_lastResults;
std::vector<ur::Group> g_viewResults;
std::wstring g_statusFull;
ur::Mode g_lastMode = ur::Mode::Urls;
std::vector<std::filesystem::path> g_chosenPaths;
uint32_t g_autoRipPid = 0;
std::vector<std::filesystem::path> g_autoRipPaths;
bool g_elevated = false;
bool g_scanDeniedFiles = false;
uint32_t g_scanPid = 0;
bool g_scanDenied = false;
bool g_scanNeedsElev = false;

std::wstring sourceArgs();
void goAdmin();
void applyFonts();
void fitColumns();
void layout(int cw, int ch);
void relayout(HWND hwnd);
void setSourcePaths(std::vector<std::filesystem::path> paths);

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

bool isMode(HWND h) { return h == g_modeUrl || h == g_modeRegex; }
bool isChip(HWND h) {
    for (HWND t : {g_ascii, g_utf16, g_b64, g_hex, g_pEmail, g_pIpv4, g_pIpv6, g_pGuid, g_pApi, g_pPath})
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

void showAbout() {
    std::string s;
    s += "StringRipper " STRINGRIPPER_VERSION "  by Akustikrausch\r\n";
    s += "build " UR_STR(STRINGRIPPER_BUILD) "  " __DATE__ "\r\n\r\n";
    s += "URLs and regex out of a process or files.\r\n";
    s += "Win32, C++20, static CRT, one exe, no DLLs.\r\n";
    s += "Scan on cores-2. URL match hand-rolled, regex via std::regex.\r\n";
    s += "ASCII/ANSI/UTF-8, UTF-16, Base64, Hex.\r\n";
    s += "Reader from Akustikrausch's FXChainPlayer.\r\n";
    s += "No third-party open source. Windows API + C++ stdlib only.\r\n";
    MessageBoxW(g_main, widen(s).c_str(), L"About StringRipper", MB_OK | MB_ICONINFORMATION);
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

void refreshProcesses() {
    g_procsAll = fxchain::ripBackend().enumerate();
    std::sort(g_procsAll.begin(), g_procsAll.end(),
              [](const fxchain::RipProcess& a, const fxchain::RipProcess& b) {
                  return _stricmp(a.name.c_str(), b.name.c_str()) < 0;
              });
    applyProcFilter();
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
    const int n = (int)g_viewResults.size();
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
        const ur::Group& g = g_viewResults[i];
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
    if (o.mode == ur::Mode::Regex) {
        if (isChecked(g_pEmail)) o.presets.push_back("email");
        if (isChecked(g_pIpv4)) o.presets.push_back("ipv4");
        if (isChecked(g_pIpv6)) o.presets.push_back("ipv6");
        if (isChecked(g_pGuid)) o.presets.push_back("guid");
        if (isChecked(g_pApi)) o.presets.push_back("apikey");
        if (isChecked(g_pPath)) o.presets.push_back("filepath");
        wchar_t cust[1024] = L"";
        GetWindowTextW(g_custom, cust, 1024);
        o.customRegex = narrow(cust);
    }
    return o;
}

void updateModeVisibility() {
    bool regex = isChecked(g_modeRegex);
    int rx = regex ? SW_SHOW : SW_HIDE;
    for (HWND h : {g_presetLabel, g_pEmail, g_pIpv4, g_pIpv6, g_pGuid, g_pApi, g_pPath, g_customLabel, g_custom})
        ShowWindow(h, rx);
    ShowWindow(g_urlHint, regex ? SW_HIDE : SW_SHOW);
}

void setScanningUi(bool on) {
    g_scanning = on;
    EnableWindow(g_scan, !on);
    EnableWindow(g_cancel, on);
    InvalidateRect(g_scan, nullptr, TRUE);
    InvalidateRect(g_cancel, nullptr, TRUE);
    if (on) { EnableWindow(g_copy, FALSE); EnableWindow(g_save, FALSE); EnableWindow(g_editor, FALSE); }
}

void enableResultActions(bool on) {
    for (HWND h : {g_copy, g_save, g_editor}) { EnableWindow(h, on); InvalidateRect(h, nullptr, TRUE); }
}

void populateResults(const std::vector<ur::Group>& groups) {
    ListView_DeleteAllItems(g_results);
    ListView_RemoveAllGroups(g_results);
    ListView_EnableGroupView(g_results, TRUE);
    int item = 0, gid = 0;
    for (const auto& g : groups) {
        std::wstring header = widen(g.name) + L"  (" + std::to_wstring(g.items.size()) + L")";
        LVGROUP lg{};
        lg.cbSize = sizeof(lg);
        lg.mask = LVGF_HEADER | LVGF_GROUPID;
        lg.pszHeader = header.data();
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
            ++item;
        }
        ++gid;
    }
    fitColumns();
}

void applyResultFilter() {
    wchar_t q[256] = L"";
    GetWindowTextW(g_filter, q, 256);
    std::string query = lower(narrow(q));
    g_viewResults.clear();
    for (const auto& g : g_lastResults) {
        if (query.empty() || lower(g.name).find(query) != std::string::npos) { g_viewResults.push_back(g); continue; }
        ur::Group hit;
        hit.name = g.name;
        for (const auto& f : g.items)
            if (lower(f.value).find(query) != std::string::npos) hit.items.push_back(f);
        if (!hit.items.empty()) g_viewResults.push_back(std::move(hit));
    }
    populateResults(g_viewResults);
    enableResultActions(!g_viewResults.empty());
    if (query.empty()) { SetWindowTextW(g_status, g_statusFull.c_str()); return; }
    wchar_t msg[128];
    _snwprintf_s(msg, _TRUNCATE, L"%zu of %zu results   (filtered)",
                 ur::countFindings(g_viewResults), ur::countFindings(g_lastResults));
    SetWindowTextW(g_status, msg);
}

void onDone(std::vector<ur::Group>* groups) {
    g_lastResults = std::move(*groups);
    delete groups;
    wchar_t msg[256];
    _snwprintf_s(msg, _TRUNCATE, L"%zu results in %zu groups, sorted Z to A   (%.2f s)%s",
                 ur::countFindings(g_lastResults), g_lastResults.size(),
                 g_elapsedMs.load() / 1000.0, g_cancelFlag ? L"  (cancelled)" : L"");
    g_statusFull = msg;
    applyResultFilter();
    setScanningUi(false);
    if (g_scanDenied) {
        if (g_scanNeedsElev && g_scanPid) {
            if (MessageBoxW(g_main, L"This process runs with higher rights. Relaunch StringRipper as administrator to scan it?",
                            L"StringRipper", MB_YESNO | MB_ICONQUESTION) == IDYES)
                fxchain::ripBackend().requestElevation(g_scanPid);
        } else {
            MessageBoxW(g_main, L"Could not open that process for reading.", L"StringRipper", MB_ICONWARNING);
        }
    } else if (g_scanDeniedFiles && !g_elevated) {
        if (MessageBoxW(g_main, L"Some of that could not be read. Relaunch StringRipper as administrator and scan it again?",
                        L"StringRipper", MB_YESNO | MB_ICONQUESTION) == IDYES)
            goAdmin();
    }
}

void setRegexMode() {
    setChecked(g_modeUrl, false);
    setChecked(g_modeRegex, true);
    updateModeVisibility();
    relayout(g_main);
}

void doScan() {
    if (g_scanning) return;
    ur::Options o = gatherOptions();
    g_lastMode = o.mode;
    try { ur::Detector probe(o); }
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
    g_scanPid = pid;
    setScanningUi(true);
    SetWindowTextW(g_filter, L"");
    SetWindowTextW(g_status, L"Scanning...");

    std::thread([o, pid, paths]() {
        auto* result = new std::vector<ur::Group>();
        bool denied = false, needsElev = false, fdenied = false;
        auto t0 = std::chrono::steady_clock::now();
        try {
            ur::Detector det(o);
            if (pid) *result = scanProcess(det, pid, [] { return g_cancelFlag.load(); }, denied, needsElev);
            else *result = scanPaths(det, paths, &fdenied);
        } catch (...) {}
        g_elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0).count();
        g_scanDenied = denied;
        g_scanNeedsElev = needsElev;
        g_scanDeniedFiles = fdenied;
        PostMessageW(g_main, WM_APP_DONE, 0, (LPARAM)result);
    }).detach();
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
    wchar_t buf[4096] = L"urlripper-results.txt";
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_main;
    ofn.lpstrFile = buf;
    ofn.nMaxFile = 4096;
    ofn.lpstrFilter = L"Text file\0*.txt\0All files\0*.*\0";
    ofn.lpstrDefExt = L"txt";
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_EXPLORER;
    if (::GetSaveFileNameW(&ofn)) {
        if (!writeTextFile(buf, resultsToText(g_viewResults, g_lastMode)))
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
    int aw2 = g_elevated ? 0 : textW(g_admin, g_font) + S(26);
    int agap = g_elevated ? 0 : sp;
    int sw2 = cw - m * 2 - rw - fw - aw2 - sp * 2 - agap;
    g_fields[0] = { m, y, m + sw2, y + rh };
    MoveWindow(g_search, m + S(6), y + S(4), sw2 - S(12), rh - S(8), TRUE);
    MoveWindow(g_refresh, right - fw - rw - aw2 - sp - agap, y, rw, rh, TRUE);
    MoveWindow(g_file, right - fw - aw2 - agap, y, fw, rh, TRUE);
    if (!g_elevated) MoveWindow(g_admin, right - aw2, y, aw2, rh, TRUE);
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
    MoveWindow(g_urlHint, m, dy + S(3), cw - m * 2, lh, TRUE);
    int lw = textW(g_customLabel, g_font) + sp;
    MoveWindow(g_presetLabel, m, dy + S(4), lw, lh, TRUE);
    flow({g_pEmail, g_pIpv4, g_pIpv6, g_pGuid, g_pApi, g_pPath}, m + lw + sp, dy, S(24));
    const int cy = dy + rh + hg;
    MoveWindow(g_customLabel, m, cy + S(4), lw, lh, TRUE);
    g_fields[2] = { m + lw + sp, cy, right, cy + rh };
    MoveWindow(g_custom, m + lw + sp + S(6), cy + S(4), right - m - lw - sp - S(12), rh - S(8), TRUE);
    y = regex ? (cy + rh + gap) : (dy + lh + gap);

    // DECODE
    MoveWindow(g_secDecode, m, y, S(200), hh, TRUE); y += hh + hg;
    flow({g_ascii, g_utf16, g_b64, g_hex}, m, y, S(24));
    y += rh + gap;

    // scan bar
    int sx = flow({g_scan, g_cancel}, m, y, S(34));
    MoveWindow(g_status, sx + sp, y + S(4), right - sx - sp, lh, TRUE);
    y += rh + gap;

    // RESULTS
    int sw = textW(g_secResults, g_fontHdr, S(2)) + sp;
    MoveWindow(g_secResults, m, y + S(6), sw, hh, TRUE);
    g_fields[3] = { m + sw + sp, y, right, y + rh };
    MoveWindow(g_filter, m + sw + sp + S(6), y + S(4), right - m - sw - sp - S(12), rh - S(8), TRUE);
    y += rh + hg;

    int bottom = ch - m - rh;
    int listH = (bottom - gap) - y;
    if (listH < S(60)) listH = S(60);
    g_listCard = { m, y, right, y + listH };
    MoveWindow(g_results, m + S(7), y + S(7), cw - m * 2 - S(14), listH - S(14), TRUE);
    fitColumns();

    flow({g_copy, g_save, g_editor}, m, bottom, S(26));
    int aw = textW(g_about, g_font) + S(26);
    MoveWindow(g_about, right - aw, bottom, aw, rh, TRUE);

}

void fitColumns() {
    RECT lc; GetClientRect(g_results, &lc);
    int encW = S(90), srcW = S(280), valW = lc.right - encW - srcW;
    if (valW < S(160)) valW = S(160);
    ListView_SetColumnWidth(g_results, 0, valW);
    ListView_SetColumnWidth(g_results, 1, encW);
    ListView_SetColumnWidth(g_results, 2, srcW);
}

std::wstring sourceArgs() {
    if (!g_chosenPaths.empty()) {
        std::wstring a = L"--rip-files";
        for (const auto& p : g_chosenPaths) a += L" \"" + p.wstring() + L"\"";
        return a;
    }
    int sel = (int)SendMessageW(g_source, CB_GETCURSEL, 0, 0);
    if (sel >= 0 && sel < (int)g_procsView.size())
        return L"--rip-pid " + std::to_wstring(g_procsView[sel].pid);
    return {};
}

void goAdmin() {
    if (!relaunchElevated(sourceArgs())) return;
    PostMessageW(g_main, WM_CLOSE, 0, 0);
}

void applyFonts() {
    for (HWND h : {g_search, g_source, g_refresh, g_file, g_srcInfo, g_modeUrl, g_modeRegex, g_urlHint,
                   g_presetLabel, g_pEmail, g_pIpv4, g_pIpv6, g_pGuid, g_pApi, g_pPath, g_customLabel,
                   g_custom, g_ascii, g_utf16, g_b64, g_hex, g_scan, g_cancel, g_status, g_filter,
                   g_results, g_copy, g_save, g_editor, g_about, g_admin})
        setFont(h, g_font);
    for (HWND h : {g_secSource, g_secFind, g_secDecode, g_secResults})
        setFont(h, g_fontHdr);
}

void relayout(HWND hwnd) {
    RECT rc; GetClientRect(hwnd, &rc);
    layout(rc.right, rc.bottom);
    InvalidateRect(hwnd, nullptr, TRUE);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
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
        g_admin = mkPush(hwnd, L"Admin", ID_ADMIN);
        ShowWindow(g_admin, g_elevated ? SW_HIDE : SW_SHOW);
        g_srcInfo = mkStatic(hwnd, L"Drop files or folders on the window, or scan the selected process.");

        g_secFind = mkSection(hwnd, L"WHAT TO FIND");
        g_modeUrl = mkButton(hwnd, L"URLs", ID_MODE_URL, BS_OWNERDRAW | WS_GROUP);
        g_modeRegex = mkButton(hwnd, L"Regex", ID_MODE_REGEX, BS_OWNERDRAW);
        setChecked(g_modeUrl, true);
        setChecked(g_modeRegex, false);
        g_urlHint = mkStatic(hwnd, L"Finds http, https, ftp, ws, wss, rtsp, rtmp and udp links, grouped by domain.");

        g_presetLabel = mkStatic(hwnd, L"Preset:");
        g_pEmail = mkChip(hwnd, L"Email", ID_P_EMAIL);
        g_pIpv4 = mkChip(hwnd, L"IPv4", ID_P_IPV4);
        g_pIpv6 = mkChip(hwnd, L"IPv6", ID_P_IPV6);
        g_pGuid = mkChip(hwnd, L"GUID", ID_P_GUID);
        g_pApi = mkChip(hwnd, L"API key", ID_P_APIKEY);
        g_pPath = mkChip(hwnd, L"File path", ID_P_PATH);
        for (HWND h : {g_pEmail, g_pIpv4, g_pIpv6, g_pGuid, g_pApi, g_pPath}) setChecked(h, h == g_pEmail);
        g_customLabel = mkStatic(hwnd, L"Custom:");
        g_custom = CreateWindowExW(0, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL, 0, 0, 0, 0, hwnd, (HMENU)ID_CUSTOM, nullptr, nullptr);
        SendMessageW(g_custom, EM_SETCUEBANNER, TRUE, (LPARAM)L"your own regex (ECMAScript)...");

        g_secDecode = mkSection(hwnd, L"DECODE");
        g_ascii = mkChip(hwnd, L"ASCII", ID_ENC_ASCII);
        g_utf16 = mkChip(hwnd, L"UTF-16", ID_ENC_UTF16);
        g_b64 = mkChip(hwnd, L"Base64", ID_ENC_B64);
        g_hex = mkChip(hwnd, L"Hex", ID_ENC_HEX);
        for (HWND h : {g_ascii, g_utf16, g_b64, g_hex}) setChecked(h, true);

        g_scan = mkPush(hwnd, L"Scan", ID_SCAN);
        g_cancel = mkPush(hwnd, L"Cancel", ID_CANCEL);
        EnableWindow(g_cancel, FALSE);
        g_status = mkStatic(hwnd, L"Ready.");

        g_secResults = mkSection(hwnd, L"RESULTS");
        g_filter = CreateWindowExW(0, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL, 0, 0, 0, 0, hwnd, (HMENU)ID_FILTER, nullptr, nullptr);
        SendMessageW(g_filter, EM_SETCUEBANNER, TRUE, (LPARAM)L"Filter results...");
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

        g_copy = mkPush(hwnd, L"Copy selected", ID_COPY);
        g_save = mkPush(hwnd, L"Save as TXT", ID_SAVE);
        g_editor = mkPush(hwnd, L"Send to editor", ID_EDITOR);
        g_about = mkPush(hwnd, L"About", ID_ABOUT);
        enableResultActions(false);

        applyFonts();

        for (HWND h : {g_search, g_custom, g_filter}) SetWindowTheme(h, L"", L"");

        BOOL dark = TRUE;
        DwmSetWindowAttribute(hwnd, 20 /*DWMWA_USE_IMMERSIVE_DARK_MODE*/, &dark, sizeof(dark));

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
        if (g_autoRipPid) {
            for (int i = 0; i < (int)g_procsView.size(); ++i)
                if (g_procsView[i].pid == g_autoRipPid) { SendMessageW(g_source, CB_SETCURSEL, i, 0); break; }
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
        case ID_MODE_URL: case ID_MODE_REGEX: {
            bool url = LOWORD(wp) == ID_MODE_URL;
            setChecked(g_modeUrl, url);
            setChecked(g_modeRegex, !url);
            updateModeVisibility(); relayout(hwnd);
            break;
        }
        case ID_SCAN: doScan(); break;
        case ID_CANCEL: g_cancelFlag = true; SetWindowTextW(g_status, L"Cancelling..."); break;
        case ID_COPY: copySelected(); break;
        case ID_SAVE: saveAsTxt(); break;
        case ID_EDITOR: sendToEditor(); break;
        case ID_ABOUT: showAbout(); break;
        case ID_ADMIN: goAdmin(); break;
        case ID_ENC_ASCII: case ID_ENC_UTF16: case ID_ENC_B64: case ID_ENC_HEX:
        case ID_P_EMAIL: case ID_P_IPV4: case ID_P_IPV6:
        case ID_P_GUID: case ID_P_APIKEY: case ID_P_PATH: {
            HWND c = (HWND)lp;
            setChecked(c, !isChecked(c));
            break;
        }
        case ID_CUSTOM:
            if (HIWORD(wp) == EN_CHANGE && GetWindowTextLengthW(g_custom) > 0) setRegexMode();
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
    case WM_NOTIFY: {
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
    case WM_DESTROY:
        g_cancelFlag = true;
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
    wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    RegisterClassExW(&wc);

    std::wstring title = L"StringRipper " STRINGRIPPER_VERSION L" by Akustikrausch";
    if (g_elevated) title += L"   [admin]";
    g_main = CreateWindowExW(0, wc.lpszClassName, title.c_str(),
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN, CW_USEDEFAULT, CW_USEDEFAULT, 1000, 760,
        nullptr, nullptr, hInst, nullptr);
    if (!g_main) return 1;
    ShowWindow(g_main, SW_SHOW);
    UpdateWindow(g_main);

    MSG m;
    while (GetMessageW(&m, nullptr, 0, 0) > 0) {
        if (IsDialogMessageW(g_main, &m)) continue;
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }
    return 0;
}

} // namespace

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int) {
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    g_elevated = elevated();
    for (int i = 1; i < __argc; ++i) {
        if (wcscmp(__wargv[i], L"--rip-pid") == 0 && i + 1 < __argc)
            g_autoRipPid = (uint32_t)wcstoul(__wargv[i + 1], nullptr, 10);
        else if (wcscmp(__wargv[i], L"--rip-files") == 0) {
            for (int j = i + 1; j < __argc; ++j) g_autoRipPaths.emplace_back(__wargv[j]);
            break;
        }
    }
    if (g_autoRipPid || !g_autoRipPaths.empty()) return runGui(hInst);
    if (__argc > 1) return runCli(__argc, __wargv);
    return runGui(hInst);
}
