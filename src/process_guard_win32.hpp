#pragma once

#include <windows.h>
#include <cstdint>
#include <cwchar>
#include <cwctype>
#include <string>

namespace ur {

/* 2: Windows needs it, never end it. 1: part of Windows, warn twice. 0: ordinary program */
/* proc: an open handle with query rights, or null to open one by pid */
inline int systemProcessLevel(uint32_t pid, const std::wstring& name, HANDLE proc = nullptr) {
    std::wstring n = name;
    for (auto& c : n) c = (wchar_t)towlower(c);
    if (n.size() > 4 && n.compare(n.size() - 4, 4, L".exe") == 0) n.resize(n.size() - 4);
    static const wchar_t* core[] = { L"system", L"registry", L"smss", L"csrss", L"wininit", L"winlogon",
                                     L"services", L"lsass", L"lsaiso", L"memory compression", L"secure system" };
    if (pid <= 4) return 2;
    for (auto* c : core) if (n == c) return 2;
    int level = 0;
    HANDLE h = proc ? proc : OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (h) {
        using Fn = BOOL (WINAPI*)(HANDLE, PBOOL);
        static auto critical = (Fn)(void*)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsProcessCritical");
        BOOL crit = FALSE;
        if (critical && critical(h, &crit) && crit) level = 2;
        wchar_t img[MAX_PATH * 2], win[MAX_PATH]; DWORD len = MAX_PATH * 2;
        const UINT wl = GetSystemWindowsDirectoryW(win, MAX_PATH);
        if (!level && wl && QueryFullProcessImageNameW(h, 0, img, &len) && len > wl &&
            _wcsnicmp(img, win, wl) == 0 && img[wl] == L'\\') level = 1;
        if (h != proc) CloseHandle(h);
    }
    DWORD session = 1;
    if (!level && ProcessIdToSessionId(pid, &session) && session == 0) level = 1;
    return level;
}

} // namespace ur
