// URLRipper - portable Windows tool.
//
// Scans a running process or files/folders for embedded URLs (URL mode) or for
// regex matches (Regex mode), decoding ASCII/ANSI/UTF-8, UTF-16, Base64 and Hex
// along the way. Findings are de-duplicated, grouped and sorted Z to A.
//
// Reading a process reuses FXChainPlayer's hardened ripper backend
// (fxchain::ripBackend(): region walk, integrity handling, image classification,
// UAC relaunch). Scanning runs multi-threaded on top of it.
//
// Safety, by design: findings are plain selectable text with NO click-to-open;
// "Save as TXT" / "Send to editor" write the file directly and NEVER use the
// clipboard; only "Copy selected" touches the clipboard.
//
// GUI when launched normally; command line when given arguments (see --help).

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

static std::string resultsToText(const std::vector<ur::Group>& groups, ur::Mode mode) {
    std::string out;
    out += (mode == ur::Mode::Urls) ? "# URLRipper - URLs\r\n" : "# URLRipper - matches\r\n";
    out += "# " + std::to_string(ur::countFindings(groups)) + " results in " +
           std::to_string(groups.size()) + " groups, sorted Z to A\r\n\r\n";
    for (const auto& g : groups) {
        out += "[" + g.name + "]  (" + std::to_string(g.items.size()) + ")\r\n";
        for (const auto& f : g.items)
            out += "  " + f.value + "\t" + ur::encName(f.enc) + "\t" + f.source + "\r\n";
        out += "\r\n";
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

// Scan a process by pid into groups. Sets accessDenied/needsElevation on failure.
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
            "URLRipper - extract URLs or regex matches from processes and files.\n\n"
            "Usage:\n"
            "  URLRipper.exe --pid N            [options]   scan a running process\n"
            "  URLRipper.exe --file PATH ...    [options]   scan files\n"
            "  URLRipper.exe --folder PATH ...  [options]   scan a folder (recursive)\n\n"
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
    ID_SOURCE = 1001, ID_REFRESH, ID_FILE, ID_MODE_URL, ID_MODE_REGEX,
    ID_ENC_ASCII, ID_ENC_UTF16, ID_ENC_B64, ID_ENC_HEX,
    ID_P_EMAIL, ID_P_IPV4, ID_P_IPV6, ID_P_GUID, ID_P_APIKEY, ID_P_PATH,
    ID_CUSTOM, ID_SCAN, ID_CANCEL, ID_RESULTS, ID_COPY, ID_SAVE, ID_EDITOR
};
constexpr UINT WM_APP_DONE = WM_APP + 1;

const COLORREF kBg = RGB(0x12, 0x12, 0x1A);
const COLORREF kBg2 = RGB(0x1A, 0x1A, 0x24);
const COLORREF kText = RGB(0xE8, 0xE8, 0xF0);

HWND g_main = nullptr;
HWND g_srcCaption, g_source, g_refresh, g_file, g_srcInfo;
HWND g_modeUrl, g_modeRegex, g_ascii, g_utf16, g_b64, g_hex;
HWND g_presetLabel, g_pEmail, g_pIpv4, g_pIpv6, g_pGuid, g_pApi, g_pPath;
HWND g_customLabel, g_custom, g_scan, g_cancel, g_status, g_results, g_copy, g_save, g_editor, g_by;
HFONT g_font = nullptr;
HBRUSH g_bgBrush = nullptr, g_bg2Brush = nullptr;

std::vector<fxchain::RipProcess> g_procs;
std::atomic<bool> g_cancelFlag{false};
std::atomic<bool> g_scanning{false};
std::vector<ur::Group> g_lastResults;
ur::Mode g_lastMode = ur::Mode::Urls;
std::wstring g_chosenFile;
uint32_t g_autoRipPid = 0;
// filled by the worker before WM_APP_DONE, read on the UI thread in onDone
uint32_t g_scanPid = 0;
bool g_scanDenied = false;
bool g_scanNeedsElev = false;

HWND mkStatic(HWND p, const wchar_t* t) {
    return CreateWindowExW(0, L"STATIC", t, WS_CHILD | WS_VISIBLE | SS_LEFT, 0, 0, 0, 0, p, nullptr, nullptr, nullptr);
}
HWND mkButton(HWND p, const wchar_t* t, int id, DWORD style = 0) {
    return CreateWindowExW(0, L"BUTTON", t, WS_CHILD | WS_VISIBLE | WS_TABSTOP | style,
                           0, 0, 0, 0, p, (HMENU)(INT_PTR)id, nullptr, nullptr);
}
void setFont(HWND h) { SendMessageW(h, WM_SETFONT, (WPARAM)g_font, TRUE); }
bool isChecked(HWND h) { return SendMessageW(h, BM_GETCHECK, 0, 0) == BST_CHECKED; }

void refreshProcesses() {
    g_procs = fxchain::ripBackend().enumerate();
    std::sort(g_procs.begin(), g_procs.end(),
              [](const fxchain::RipProcess& a, const fxchain::RipProcess& b) {
                  return _stricmp(a.name.c_str(), b.name.c_str()) < 0;
              });
    SendMessageW(g_source, CB_RESETCONTENT, 0, 0);
    for (const auto& p : g_procs) {
        wchar_t line[256];
        _snwprintf_s(line, _TRUNCATE, L"%s   (pid %u, %llu MB%s%s)",
                     widen(p.name).c_str(), p.pid,
                     (unsigned long long)(p.workingSetBytes / (1024 * 1024)),
                     p.bits == 32 ? L", 32-bit" : L"",
                     p.access == fxchain::RipAccess::NeedsElevation ? L", needs admin" : L"");
        SendMessageW(g_source, CB_ADDSTRING, 0, (LPARAM)line);
    }
    if (!g_procs.empty()) SendMessageW(g_source, CB_SETCURSEL, 0, 0);
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

void setScanningUi(bool on) {
    g_scanning = on;
    EnableWindow(g_scan, !on);
    EnableWindow(g_cancel, on);
    EnableWindow(g_copy, !on);
    EnableWindow(g_save, !on);
    EnableWindow(g_editor, !on);
}

void setRegexMode() {
    SendMessageW(g_modeUrl, BM_SETCHECK, BST_UNCHECKED, 0);
    SendMessageW(g_modeRegex, BM_SETCHECK, BST_CHECKED, 0);
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
    std::wstring msg = std::to_wstring(ur::countFindings(g_lastResults)) + L" results in " +
                       std::to_wstring(g_lastResults.size()) + L" groups, sorted Z to A";
    if (g_cancelFlag) msg += L" (cancelled)";
    SetWindowTextW(g_status, msg.c_str());
    setScanningUi(false);
    if (g_scanDenied) {
        if (g_scanNeedsElev && g_scanPid) {
            if (MessageBoxW(g_main, L"This process runs with higher rights. Relaunch URLRipper as administrator to scan it?",
                            L"URLRipper", MB_YESNO | MB_ICONQUESTION) == IDYES)
                fxchain::ripBackend().requestElevation(g_scanPid);
        } else {
            MessageBoxW(g_main, L"Could not open that process for reading.", L"URLRipper", MB_ICONWARNING);
        }
    }
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
        if (sel >= 0 && sel < (int)g_procs.size()) pid = g_procs[sel].pid;
    }
    if (!pid && file.empty()) {
        MessageBoxW(g_main, L"Choose a process or a file first.", L"URLRipper", MB_ICONINFORMATION);
        return;
    }

    g_cancelFlag = false;
    g_scanPid = pid;
    setScanningUi(true);
    SetWindowTextW(g_status, L"Scanning...");

    std::thread([o, pid, file]() {
        auto* result = new std::vector<ur::Group>();
        bool denied = false, needsElev = false;
        try {
            ur::Detector det(o);
            if (pid) {
                *result = scanProcess(det, pid, [] { return g_cancelFlag.load(); }, denied, needsElev);
            } else {
                *result = scanPaths(det, {std::filesystem::path(file)});
            }
        } catch (...) {}
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
            MessageBoxW(g_main, L"Could not write the file.", L"URLRipper", MB_ICONERROR);
    }
}

void sendToEditor() {
    if (g_lastResults.empty()) return;
    wchar_t tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    std::wstring p = std::wstring(tmp) + L"URLRipper-" + std::to_wstring(GetTickCount64()) + L".txt";
    if (!writeTextFile(p, resultsToText(g_lastResults, g_lastMode))) {
        MessageBoxW(g_main, L"Could not write the temp file.", L"URLRipper", MB_ICONERROR);
        return;
    }
    ::ShellExecuteW(g_main, L"open", p.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
}

void layout(int cw, int ch) {
    const int m = 12, rh = 24, gap = 8;
    int y = m;
    MoveWindow(g_srcCaption, m, y + 3, 55, rh, TRUE);
    MoveWindow(g_source, m + 60, y, cw - m * 2 - 60 - 180, 360, TRUE);
    MoveWindow(g_refresh, cw - m - 174, y, 84, rh, TRUE);
    MoveWindow(g_file, cw - m - 84, y, 84, rh, TRUE);
    y += rh + 4;
    MoveWindow(g_srcInfo, m, y, cw - m * 2, 18, TRUE);
    y += 18 + gap;

    MoveWindow(g_modeUrl, m, y, 66, rh, TRUE);
    MoveWindow(g_modeRegex, m + 70, y, 74, rh, TRUE);
    int ex = m + 160;
    MoveWindow(g_ascii, ex, y, 66, rh, TRUE);
    MoveWindow(g_utf16, ex + 70, y, 74, rh, TRUE);
    MoveWindow(g_b64, ex + 150, y, 74, rh, TRUE);
    MoveWindow(g_hex, ex + 228, y, 58, rh, TRUE);
    y += rh + gap;

    MoveWindow(g_presetLabel, m, y + 3, 55, 18, TRUE);
    int px = m + 60;
    MoveWindow(g_pEmail, px, y, 66, rh, TRUE);
    MoveWindow(g_pIpv4, px + 68, y, 58, rh, TRUE);
    MoveWindow(g_pIpv6, px + 128, y, 58, rh, TRUE);
    MoveWindow(g_pGuid, px + 188, y, 62, rh, TRUE);
    MoveWindow(g_pApi, px + 252, y, 76, rh, TRUE);
    MoveWindow(g_pPath, px + 330, y, 82, rh, TRUE);
    y += rh + 4;
    MoveWindow(g_customLabel, m, y + 3, 55, 18, TRUE);
    MoveWindow(g_custom, m + 60, y, cw - m * 2 - 60, rh, TRUE);
    y += rh + gap;

    MoveWindow(g_scan, m, y, 100, rh + 2, TRUE);
    MoveWindow(g_cancel, m + 108, y, 90, rh + 2, TRUE);
    MoveWindow(g_status, m + 210, y + 4, cw - m * 2 - 210, 18, TRUE);
    y += rh + 2 + gap;

    int bottom = ch - m - rh;
    MoveWindow(g_results, m, y, cw - m * 2, (bottom - gap) - y, TRUE);
    MoveWindow(g_copy, m, bottom, 120, rh, TRUE);
    MoveWindow(g_save, m + 128, bottom, 120, rh, TRUE);
    MoveWindow(g_editor, m + 256, bottom, 140, rh, TRUE);
    MoveWindow(g_by, cw - m - 170, bottom + 4, 170, 18, TRUE);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        g_font = CreateFontW(-15, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
                             OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                             DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
        g_bgBrush = CreateSolidBrush(kBg);
        g_bg2Brush = CreateSolidBrush(kBg2);

        g_srcCaption = mkStatic(hwnd, L"Source:");
        g_source = CreateWindowExW(0, L"COMBOBOX", L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL,
            0, 0, 0, 0, hwnd, (HMENU)ID_SOURCE, nullptr, nullptr);
        g_refresh = mkButton(hwnd, L"Refresh", ID_REFRESH);
        g_file = mkButton(hwnd, L"File...", ID_FILE);
        g_srcInfo = mkStatic(hwnd, L"No file chosen; scanning the selected process.");

        g_modeUrl = mkButton(hwnd, L"URLs", ID_MODE_URL, BS_AUTORADIOBUTTON | WS_GROUP);
        g_modeRegex = mkButton(hwnd, L"Regex", ID_MODE_REGEX, BS_AUTORADIOBUTTON);
        SendMessageW(g_modeUrl, BM_SETCHECK, BST_CHECKED, 0);

        g_ascii = mkButton(hwnd, L"ASCII", ID_ENC_ASCII, BS_AUTOCHECKBOX);
        g_utf16 = mkButton(hwnd, L"UTF-16", ID_ENC_UTF16, BS_AUTOCHECKBOX);
        g_b64 = mkButton(hwnd, L"Base64", ID_ENC_B64, BS_AUTOCHECKBOX);
        g_hex = mkButton(hwnd, L"Hex", ID_ENC_HEX, BS_AUTOCHECKBOX);
        for (HWND h : {g_ascii, g_utf16, g_b64, g_hex}) SendMessageW(h, BM_SETCHECK, BST_CHECKED, 0);

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
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
            0, 0, 0, 0, hwnd, (HMENU)ID_CUSTOM, nullptr, nullptr);

        g_scan = mkButton(hwnd, L"Scan", ID_SCAN, BS_DEFPUSHBUTTON);
        g_cancel = mkButton(hwnd, L"Cancel", ID_CANCEL);
        EnableWindow(g_cancel, FALSE);
        g_status = mkStatic(hwnd, L"Ready.");

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
        g_by = CreateWindowExW(0, L"STATIC", L"by Akustikrausch",
            WS_CHILD | WS_VISIBLE | SS_RIGHT, 0, 0, 0, 0, hwnd, nullptr, nullptr, nullptr);

        for (HWND h : {g_srcCaption, g_source, g_refresh, g_file, g_srcInfo, g_modeUrl, g_modeRegex,
                       g_ascii, g_utf16, g_b64, g_hex, g_presetLabel, g_pEmail, g_pIpv4, g_pIpv6,
                       g_pGuid, g_pApi, g_pPath, g_customLabel, g_custom, g_scan, g_cancel, g_status,
                       g_results, g_copy, g_save, g_editor, g_by})
            setFont(h);

        BOOL dark = TRUE;
        DwmSetWindowAttribute(hwnd, 20 /*DWMWA_USE_IMMERSIVE_DARK_MODE*/, &dark, sizeof(dark));

        refreshProcesses();
        if (g_autoRipPid) {
            for (int i = 0; i < (int)g_procs.size(); ++i)
                if (g_procs[i].pid == g_autoRipPid) { SendMessageW(g_source, CB_SETCURSEL, i, 0); break; }
            PostMessageW(hwnd, WM_COMMAND, ID_SCAN, 0);
        }
        return 0;
    }
    case WM_SIZE:
        layout(LOWORD(lp), HIWORD(lp));
        return 0;
    case WM_CTLCOLORSTATIC:
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
        case ID_REFRESH: refreshProcesses(); break;
        case ID_FILE: pickFile(); break;
        case ID_SCAN: doScan(); break;
        case ID_CANCEL: g_cancelFlag = true; SetWindowTextW(g_status, L"Cancelling..."); break;
        case ID_COPY: copySelected(); break;
        case ID_SAVE: saveAsTxt(); break;
        case ID_EDITOR: sendToEditor(); break;
        case ID_P_EMAIL: case ID_P_IPV4: case ID_P_IPV6:
        case ID_P_GUID: case ID_P_APIKEY: case ID_P_PATH:
            if (isChecked((HWND)lp)) setRegexMode();
            break;
        case ID_CUSTOM:
            if (HIWORD(wp) == EN_CHANGE && GetWindowTextLengthW(g_custom) > 0) setRegexMode();
            break;
        case ID_SOURCE:
            if (HIWORD(wp) == CBN_SELCHANGE) {
                g_chosenFile.clear();
                int sel = (int)SendMessageW(g_source, CB_GETCURSEL, 0, 0);
                if (sel >= 0 && sel < (int)g_procs.size())
                    SetWindowTextW(g_srcInfo, (L"Scanning process: " + widen(g_procs[sel].name) +
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
    wc.lpszClassName = L"URLRipperWindow";
    wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    RegisterClassExW(&wc);

    g_main = CreateWindowExW(0, wc.lpszClassName, L"URLRipper",
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 980, 720,
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
    // FXChainPlayer's ripper relaunches elevated with "--rip-pid N"; honor it by
    // opening the GUI pre-targeted at that process.
    for (int i = 1; i < __argc; ++i)
        if (wcscmp(__wargv[i], L"--rip-pid") == 0 && i + 1 < __argc)
            g_autoRipPid = (uint32_t)wcstoul(__wargv[i + 1], nullptr, 10);
    if (g_autoRipPid) return runGui(hInst);
    if (__argc > 1) return runCli(__argc, __wargv);
    return runGui(hInst);
}
