// Windows only: which processes Kill refuses or warns about
#include "../src/process_guard_win32.hpp"
#include <tlhelp32.h>
#include <cstdio>

static int failures = 0;
#define CHECK(c) do { if (!(c)) { std::printf("FAIL line %d: %s\n", __LINE__, #c); ++failures; } } while (0)

static DWORD pidOf(const wchar_t* exe) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe{sizeof(pe)};
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) do if (!_wcsicmp(pe.szExeFile, exe)) { pid = pe.th32ProcessID; break; } while (Process32NextW(snap, &pe));
    CloseHandle(snap);
    return pid;
}

int main() {
    CHECK(ur::systemProcessLevel(4, L"System") == 2);
    for (const wchar_t* n : {L"csrss.exe", L"lsass.exe", L"winlogon.exe"}) {                  // found, and refused by name alone
        DWORD p = pidOf(n);
        CHECK(p > 4);
        CHECK(ur::systemProcessLevel(p, n) == 2);
    }
    CHECK(ur::systemProcessLevel(12345678, L"LSASS.EXE") == 2);
    if (DWORD p = pidOf(L"spoolsv.exe"))                                                          // a service: only when we may look at it
        if (HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, p)) { CloseHandle(h); CHECK(ur::systemProcessLevel(p, L"spoolsv.exe") >= 1); }
    if (DWORD p = pidOf(L"explorer.exe")) CHECK(ur::systemProcessLevel(p, L"explorer.exe") == 1);  // Windows folder
    DWORD session = 0;                                                                            // ordinary program, unless run as a service
    if (ProcessIdToSessionId(GetCurrentProcessId(), &session) && session) CHECK(ur::systemProcessLevel(GetCurrentProcessId(), L"test_process_guard.exe") == 0);
    if (HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId()); h && session) {
        CHECK(ur::systemProcessLevel(GetCurrentProcessId(), L"test_process_guard.exe", h) == 0);  // caller's handle, left open
        CHECK(GetProcessId(h) == GetCurrentProcessId());
        CloseHandle(h);
    }
    std::printf(failures ? "%d failures\n" : "ok\n", failures);
    return failures ? 1 : 0;
}
