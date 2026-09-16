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

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(linker, "\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#ifndef STRINGRIPPER_VERSION
#define STRINGRIPPER_VERSION "1.0.0"
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

// ---------------------------------------------------------------- shared text

static std::string resultsToText(const std::vector<ur::Group>& groups, ur::Mode) {
    std::string out;
    for (const auto& g : groups) {
        if (!out.empty()) out += "\r\n";
        out += g.name + "  (" + std::to_string(g.items.size()) + ")\r\n";
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
                                        const std::vector<std::filesystem::path>& inputs) {
    ur::DriverLimits lim;
    ur::ScanPool pool(det, 0, kMaxInFlight);
    for (const auto& f : ur::expandInputs(inputs))
        ur::scanFileInto(f, pool, lim);
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
            "Reading a process reuses FXChainPlayer's ripper backend; scanning is multi-threaded.\n");
        return help ? 0 : 2;
    }

    std::unique_ptr<ur::Detector> det;
    try { det = std::make_unique<ur::Detector>(o); }
    catch (const ur::RegexError& e) { std::fprintf(stderr, "error: %s\n", e.what()); return 2; }

    std::vector<ur::Group> groups;
    if (pid) {
        bool denied = false, needsElev = false;
        groups = scanProcess(*det, pid, {}, denied, needsElev);
        if (denied) {
            std::fprintf(stderr, "error: cannot open pid %lu%s\n", (unsigned long)pid,
                         needsElev ? " (needs elevation: run as administrator)" : "");
            return 2;
        }
    } else {
        groups = scanPaths(*det, inputs);
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
    ID_CUSTOM, ID_SCAN, ID_CANCEL, ID_RESULTS, ID_COPY, ID_SAVE, ID_EDITOR, ID_ABOUT
};
constexpr UINT WM_APP_DONE = WM_APP + 1;

const COLORREF kBg = RGB(0x12, 0x12, 0x1A);
const COLORREF kBg2 = RGB(0x1A, 0x1A, 0x24);
const COLORREF kText = RGB(0xE8, 0xE8, 0xF0);
const COLORREF kText3 = RGB(0x78, 0x78, 0xA0);

HWND g_main = nullptr;
HWND g_secSource, g_search, g_source, g_refresh, g_file, g_srcInfo;
HWND g_secFind, g_modeUrl, g_modeRegex, g_urlHint;
HWND g_presetLabel, g_pEmail, g_pIpv4, g_pIpv6, g_pGuid, g_pApi, g_pPath, g_customLabel, g_custom;
HWND g_secDecode, g_ascii, g_utf16, g_b64, g_hex;
HWND g_scan, g_cancel, g_status;
HWND g_secResults, g_results, g_copy, g_save, g_editor, g_about;
HFONT g_font = nullptr, g_fontHdr = nullptr;
HBRUSH g_bgBrush = nullptr, g_bg2Brush = nullptr;

std::vector<fxchain::RipProcess> g_procsAll;   // full enumeration
std::vector<fxchain::RipProcess> g_procsView;  // what the combo currently shows
std::atomic<bool> g_cancelFlag{false};
std::atomic<bool> g_scanning{false};
std::atomic<long long> g_elapsedMs{0};
std::vector<ur::Group> g_lastResults;
ur::Mode g_lastMode = ur::Mode::Urls;
std::wstring g_chosenFile;
uint32_t g_autoRipPid = 0;
uint32_t g_scanPid = 0;
bool g_scanDenied = false;
bool g_scanNeedsElev = false;

void layout(int cw, int ch);
void relayout(HWND hwnd);

HWND mkStatic(HWND p, const wchar_t* t, DWORD extra = 0) {
    return CreateWindowExW(0, L"STATIC", t, WS_CHILD | WS_VISIBLE | SS_LEFT | extra,
                           0, 0, 0, 0, p, nullptr, nullptr, nullptr);
}
HWND mkButton(HWND p, const wchar_t* t, int id, DWORD style = 0) {
    return CreateWindowExW(0, L"BUTTON", t, WS_CHILD | WS_VISIBLE | WS_TABSTOP | style,
                           0, 0, 0, 0, p, (HMENU)(INT_PTR)id, nullptr, nullptr);
}
void setFont(HWND h, HFONT f) { SendMessageW(h, WM_SETFONT, (WPARAM)f, TRUE); }
bool isChecked(HWND h) { return SendMessageW(h, BM_GETCHECK, 0, 0) == BST_CHECKED; }

void showAbout() {
    std::string s;
    s += "StringRipper " STRINGRIPPER_VERSION "\r\n";
    s += "by Akustikrausch\r\n";
    s += "Build " UR_STR(STRINGRIPPER_BUILD) ", built " __DATE__ " " __TIME__ "\r\n\r\n";
    s += "Extracts URLs and regex matches from running processes and files.\r\n\r\n";
    s += "Technical\r\n";
    s += "  Windows x64, C++20, native Win32 GUI (no UI framework).\r\n";
    s += "  Single portable exe, static C runtime, no DLLs to ship.\r\n";
    s += "  Multi-threaded scan: one reader thread feeds a worker pool of (cores - 2).\r\n";
    s += "  URL matching is hand-rolled (no regex); regex mode uses std::regex.\r\n";
    s += "  Decodes ASCII/ANSI/UTF-8, UTF-16 LE/BE, Base64 and Hex.\r\n";
    s += "  Process memory is read through FXChainPlayer's ripper backend.\r\n\r\n";
    s += "Open source\r\n";
    s += "  No third-party open-source components are bundled.\r\n";
    s += "  Built on the Windows API and the C++ standard library only.\r\n";
    s += "  The process reader is reused from Akustikrausch's FXChainPlayer.\r\n";
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
    std::string query = narrow(q);
    std::transform(query.begin(), query.end(), query.begin(), [](unsigned char c) { return char(std::tolower(c)); });
    g_procsView.clear();
    for (const auto& p : g_procsAll) {
        if (query.empty()) { g_procsView.push_back(p); continue; }
        std::string name = p.name;
        std::transform(name.begin(), name.end(), name.begin(), [](unsigned char c) { return char(std::tolower(c)); });
        if (name.find(query) != std::string::npos) g_procsView.push_back(p);
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
    if (::GetOpenFileNameW(&ofn)) {
        g_chosenFile = buf;
        SetWindowTextW(g_srcInfo, (L"File: " + g_chosenFile + L"   (pick a process to clear)").c_str());
    }
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
    if (on) { EnableWindow(g_copy, FALSE); EnableWindow(g_save, FALSE); EnableWindow(g_editor, FALSE); }
}

void enableResultActions(bool on) {
    EnableWindow(g_copy, on);
    EnableWindow(g_save, on);
    EnableWindow(g_editor, on);
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
}

void onDone(std::vector<ur::Group>* groups) {
    g_lastResults = std::move(*groups);
    delete groups;
    populateResults(g_lastResults);
    wchar_t msg[256];
    _snwprintf_s(msg, _TRUNCATE, L"%zu results in %zu groups, sorted Z to A   (%.2f s)%s",
                 ur::countFindings(g_lastResults), g_lastResults.size(),
                 g_elapsedMs.load() / 1000.0, g_cancelFlag ? L"  (cancelled)" : L"");
    SetWindowTextW(g_status, msg);
    setScanningUi(false);
    enableResultActions(!g_lastResults.empty());
    if (g_scanDenied) {
        if (g_scanNeedsElev && g_scanPid) {
            if (MessageBoxW(g_main, L"This process runs with higher rights. Relaunch StringRipper as administrator to scan it?",
                            L"StringRipper", MB_YESNO | MB_ICONQUESTION) == IDYES)
                fxchain::ripBackend().requestElevation(g_scanPid);
        } else {
            MessageBoxW(g_main, L"Could not open that process for reading.", L"StringRipper", MB_ICONWARNING);
        }
    }
}

void setRegexMode() {
    SendMessageW(g_modeUrl, BM_SETCHECK, BST_UNCHECKED, 0);
    SendMessageW(g_modeRegex, BM_SETCHECK, BST_CHECKED, 0);
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
    std::wstring file = g_chosenFile;
    if (file.empty()) {
        int sel = (int)SendMessageW(g_source, CB_GETCURSEL, 0, 0);
        if (sel >= 0 && sel < (int)g_procsView.size()) pid = g_procsView[sel].pid;
    }
    if (!pid && file.empty()) {
        MessageBoxW(g_main, L"Choose a process or a file first.", L"StringRipper", MB_ICONINFORMATION);
        return;
    }

    g_cancelFlag = false;
    g_scanPid = pid;
    setScanningUi(true);
    SetWindowTextW(g_status, L"Scanning...");

    std::thread([o, pid, file]() {
        auto* result = new std::vector<ur::Group>();
        bool denied = false, needsElev = false;
        auto t0 = std::chrono::steady_clock::now();
        try {
            ur::Detector det(o);
            if (pid) *result = scanProcess(det, pid, [] { return g_cancelFlag.load(); }, denied, needsElev);
            else *result = scanPaths(det, {std::filesystem::path(file)});
        } catch (...) {}
        g_elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0).count();
        g_scanDenied = denied;
        g_scanNeedsElev = needsElev;
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
    if (g_lastResults.empty()) return;
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
        if (!writeTextFile(buf, resultsToText(g_lastResults, g_lastMode)))
            MessageBoxW(g_main, L"Could not write the file.", L"StringRipper", MB_ICONERROR);
    }
}

void sendToEditor() {
    if (g_lastResults.empty()) return;
    wchar_t tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    std::wstring p = std::wstring(tmp) + L"StringRipper-" + std::to_wstring(GetTickCount64()) + L".txt";
    if (!writeTextFile(p, resultsToText(g_lastResults, g_lastMode))) {
        MessageBoxW(g_main, L"Could not write the temp file.", L"StringRipper", MB_ICONERROR);
        return;
    }
    ::ShellExecuteW(g_main, L"open", p.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
}

void layout(int cw, int ch) {
    const int m = 12, rh = 24, gap = 10, hh = 16, lh = 19;
    const bool regex = isChecked(g_modeRegex);
    int y = m;

    // SOURCE
    MoveWindow(g_secSource, m, y, 200, hh, TRUE); y += hh + 3;
    MoveWindow(g_search, m, y, cw - m * 2 - 180, rh, TRUE);
    MoveWindow(g_refresh, cw - m - 174, y, 84, rh, TRUE);
    MoveWindow(g_file, cw - m - 84, y, 84, rh, TRUE);
    y += rh + 4;
    MoveWindow(g_source, m, y, cw - m * 2, 360, TRUE);   // 360 = dropdown height
    y += rh + 3;
    MoveWindow(g_srcInfo, m, y, cw - m * 2, lh, TRUE);
    y += lh + gap;

    // WHAT TO FIND
    MoveWindow(g_secFind, m, y, 200, hh, TRUE); y += hh + 3;
    MoveWindow(g_modeUrl, m, y, 66, rh, TRUE);
    MoveWindow(g_modeRegex, m + 70, y, 74, rh, TRUE);
    y += rh + 3;
    const int detailY = y;
    MoveWindow(g_urlHint, m, detailY + 3, cw - m * 2, lh, TRUE);
    MoveWindow(g_presetLabel, m, detailY + 4, 55, lh, TRUE);
    int px = m + 60;
    MoveWindow(g_pEmail, px, detailY, 66, rh, TRUE);
    MoveWindow(g_pIpv4, px + 68, detailY, 58, rh, TRUE);
    MoveWindow(g_pIpv6, px + 128, detailY, 58, rh, TRUE);
    MoveWindow(g_pGuid, px + 188, detailY, 62, rh, TRUE);
    MoveWindow(g_pApi, px + 252, detailY, 76, rh, TRUE);
    MoveWindow(g_pPath, px + 330, detailY, 82, rh, TRUE);
    MoveWindow(g_customLabel, m, detailY + rh + 6 + 4, 55, lh, TRUE);
    MoveWindow(g_custom, m + 60, detailY + rh + 6, cw - m * 2 - 60, rh, TRUE);
    y = regex ? (detailY + rh + 6 + rh + gap) : (detailY + lh + gap);

    // DECODE
    MoveWindow(g_secDecode, m, y, 200, hh, TRUE); y += hh + 3;
    MoveWindow(g_ascii, m, y, 66, rh, TRUE);
    MoveWindow(g_utf16, m + 70, y, 74, rh, TRUE);
    MoveWindow(g_b64, m + 150, y, 74, rh, TRUE);
    MoveWindow(g_hex, m + 228, y, 58, rh, TRUE);
    y += rh + gap;

    // scan bar
    MoveWindow(g_scan, m, y, 100, rh + 2, TRUE);
    MoveWindow(g_cancel, m + 108, y, 90, rh + 2, TRUE);
    MoveWindow(g_status, m + 210, y + 3, cw - m * 2 - 210, lh, TRUE);
    y += rh + 2 + gap;

    // RESULTS
    MoveWindow(g_secResults, m, y, 300, hh, TRUE);
    y += hh + 3;
    int bottom = ch - m - rh;
    int listH = (bottom - gap) - y;
    if (listH < 60) listH = 60;
    MoveWindow(g_results, m, y, cw - m * 2, listH, TRUE);
    int listW = cw - m * 2 - 24;
    int valW = listW - 90 - 220;
    ListView_SetColumnWidth(g_results, 0, valW > 160 ? valW : 160);

    MoveWindow(g_copy, m, bottom, 120, rh, TRUE);
    MoveWindow(g_save, m + 128, bottom, 120, rh, TRUE);
    MoveWindow(g_editor, m + 256, bottom, 140, rh, TRUE);
    MoveWindow(g_about, cw - m - 84, bottom, 84, rh, TRUE);
}

void relayout(HWND hwnd) {
    RECT rc; GetClientRect(hwnd, &rc);
    layout(rc.right, rc.bottom);
    InvalidateRect(hwnd, nullptr, TRUE);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        g_font = CreateFontW(-15, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
                             OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                             DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
        g_fontHdr = CreateFontW(-12, 0, 0, 0, FW_SEMIBOLD, 0, 0, 0, DEFAULT_CHARSET,
                                OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                                DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
        g_bgBrush = CreateSolidBrush(kBg);
        g_bg2Brush = CreateSolidBrush(kBg2);

        g_secSource = mkStatic(hwnd, L"SOURCE");
        g_search = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL, 0, 0, 0, 0, hwnd, (HMENU)ID_SEARCH, nullptr, nullptr);
        SendMessageW(g_search, EM_SETCUEBANNER, TRUE, (LPARAM)L"Filter processes by name...");
        g_source = CreateWindowExW(0, L"COMBOBOX", L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL,
            0, 0, 0, 0, hwnd, (HMENU)ID_SOURCE, nullptr, nullptr);
        g_refresh = mkButton(hwnd, L"Refresh", ID_REFRESH);
        g_file = mkButton(hwnd, L"File...", ID_FILE);
        g_srcInfo = mkStatic(hwnd, L"No file chosen; scanning the selected process.");

        g_secFind = mkStatic(hwnd, L"WHAT TO FIND");
        g_modeUrl = mkButton(hwnd, L"URLs", ID_MODE_URL, BS_AUTORADIOBUTTON | WS_GROUP);
        g_modeRegex = mkButton(hwnd, L"Regex", ID_MODE_REGEX, BS_AUTORADIOBUTTON);
        SendMessageW(g_modeUrl, BM_SETCHECK, BST_CHECKED, 0);
        g_urlHint = mkStatic(hwnd, L"Finds http, https, ftp, ws, wss, rtsp, rtmp and udp links, grouped by domain.");

        g_presetLabel = mkStatic(hwnd, L"Preset:");
        g_pEmail = mkButton(hwnd, L"Email", ID_P_EMAIL, BS_AUTOCHECKBOX);
        g_pIpv4 = mkButton(hwnd, L"IPv4", ID_P_IPV4, BS_AUTOCHECKBOX);
        g_pIpv6 = mkButton(hwnd, L"IPv6", ID_P_IPV6, BS_AUTOCHECKBOX);
        g_pGuid = mkButton(hwnd, L"GUID", ID_P_GUID, BS_AUTOCHECKBOX);
        g_pApi = mkButton(hwnd, L"API key", ID_P_APIKEY, BS_AUTOCHECKBOX);
        g_pPath = mkButton(hwnd, L"File path", ID_P_PATH, BS_AUTOCHECKBOX);
        SendMessageW(g_pEmail, BM_SETCHECK, BST_CHECKED, 0);
        g_customLabel = mkStatic(hwnd, L"Custom:");
        g_custom = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL, 0, 0, 0, 0, hwnd, (HMENU)ID_CUSTOM, nullptr, nullptr);
        SendMessageW(g_custom, EM_SETCUEBANNER, TRUE, (LPARAM)L"your own regex (ECMAScript)...");

        g_secDecode = mkStatic(hwnd, L"DECODE");
        g_ascii = mkButton(hwnd, L"ASCII", ID_ENC_ASCII, BS_AUTOCHECKBOX);
        g_utf16 = mkButton(hwnd, L"UTF-16", ID_ENC_UTF16, BS_AUTOCHECKBOX);
        g_b64 = mkButton(hwnd, L"Base64", ID_ENC_B64, BS_AUTOCHECKBOX);
        g_hex = mkButton(hwnd, L"Hex", ID_ENC_HEX, BS_AUTOCHECKBOX);
        for (HWND h : {g_ascii, g_utf16, g_b64, g_hex}) SendMessageW(h, BM_SETCHECK, BST_CHECKED, 0);

        g_scan = mkButton(hwnd, L"Scan", ID_SCAN, BS_DEFPUSHBUTTON);
        g_cancel = mkButton(hwnd, L"Cancel", ID_CANCEL);
        EnableWindow(g_cancel, FALSE);
        g_status = mkStatic(hwnd, L"Ready.");

        g_secResults = mkStatic(hwnd, L"RESULTS");
        g_results = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SHOWSELALWAYS,
            0, 0, 0, 0, hwnd, (HMENU)ID_RESULTS, nullptr, nullptr);
        ListView_SetExtendedListViewStyle(g_results, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
        ListView_SetBkColor(g_results, kBg2);
        ListView_SetTextBkColor(g_results, kBg2);
        ListView_SetTextColor(g_results, kText);
        LVCOLUMNW col{};
        col.mask = LVCF_TEXT | LVCF_WIDTH;
        col.cx = 520; col.pszText = (LPWSTR)L"Value"; ListView_InsertColumn(g_results, 0, &col);
        col.cx = 90;  col.pszText = (LPWSTR)L"Encoding"; ListView_InsertColumn(g_results, 1, &col);
        col.cx = 220; col.pszText = (LPWSTR)L"Source"; ListView_InsertColumn(g_results, 2, &col);

        g_copy = mkButton(hwnd, L"Copy selected", ID_COPY);
        g_save = mkButton(hwnd, L"Save as TXT", ID_SAVE);
        g_editor = mkButton(hwnd, L"Send to editor", ID_EDITOR);
        g_about = mkButton(hwnd, L"About", ID_ABOUT);
        enableResultActions(false);

        for (HWND h : {g_search, g_source, g_refresh, g_file, g_srcInfo, g_modeUrl, g_modeRegex, g_urlHint,
                       g_presetLabel, g_pEmail, g_pIpv4, g_pIpv6, g_pGuid, g_pApi, g_pPath, g_customLabel,
                       g_custom, g_ascii, g_utf16, g_b64, g_hex, g_scan, g_cancel, g_status, g_results,
                       g_copy, g_save, g_editor, g_about})
            setFont(h, g_font);
        for (HWND h : {g_secSource, g_secFind, g_secDecode, g_secResults})
            setFont(h, g_fontHdr);

        BOOL dark = TRUE;
        DwmSetWindowAttribute(hwnd, 20 /*DWMWA_USE_IMMERSIVE_DARK_MODE*/, &dark, sizeof(dark));

        refreshProcesses();
        updateModeVisibility();
        if (g_autoRipPid) {
            for (int i = 0; i < (int)g_procsView.size(); ++i)
                if (g_procsView[i].pid == g_autoRipPid) { SendMessageW(g_source, CB_SETCURSEL, i, 0); break; }
            PostMessageW(hwnd, WM_COMMAND, ID_SCAN, 0);
        }
        return 0;
    }
    case WM_SIZE:
        layout(LOWORD(lp), HIWORD(lp));
        return 0;
    case WM_GETMINMAXINFO: {
        auto* mmi = (MINMAXINFO*)lp;
        mmi->ptMinTrackSize.x = 780;
        mmi->ptMinTrackSize.y = 580;
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
    case WM_ERASEBKGND: {
        RECT rc; GetClientRect(hwnd, &rc);
        FillRect((HDC)wp, &rc, g_bgBrush);
        return 1;
    }
    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case ID_SEARCH: if (HIWORD(wp) == EN_CHANGE) applyProcFilter(); break;
        case ID_REFRESH: refreshProcesses(); break;
        case ID_FILE: pickFile(); break;
        case ID_MODE_URL: case ID_MODE_REGEX: updateModeVisibility(); relayout(hwnd); break;
        case ID_SCAN: doScan(); break;
        case ID_CANCEL: g_cancelFlag = true; SetWindowTextW(g_status, L"Cancelling..."); break;
        case ID_COPY: copySelected(); break;
        case ID_SAVE: saveAsTxt(); break;
        case ID_EDITOR: sendToEditor(); break;
        case ID_ABOUT: showAbout(); break;
        case ID_CUSTOM:
            if (HIWORD(wp) == EN_CHANGE && GetWindowTextLengthW(g_custom) > 0) setRegexMode();
            break;
        case ID_SOURCE:
            if (HIWORD(wp) == CBN_SELCHANGE) {
                g_chosenFile.clear();
                int sel = (int)SendMessageW(g_source, CB_GETCURSEL, 0, 0);
                if (sel >= 0 && sel < (int)g_procsView.size())
                    SetWindowTextW(g_srcInfo, (L"Scanning process: " + widen(g_procsView[sel].name) +
                        L"   (or pick a file)").c_str());
            }
            break;
        }
        return 0;
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

    g_main = CreateWindowExW(0, wc.lpszClassName, L"StringRipper " STRINGRIPPER_VERSION L" by Akustikrausch",
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 1000, 760,
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
    for (int i = 1; i < __argc; ++i)
        if (wcscmp(__wargv[i], L"--rip-pid") == 0 && i + 1 < __argc)
            g_autoRipPid = (uint32_t)wcstoul(__wargv[i + 1], nullptr, 10);
    if (g_autoRipPid) return runGui(hInst);
    if (__argc > 1) return runCli(__argc, __wargv);
    return runGui(hInst);
}
