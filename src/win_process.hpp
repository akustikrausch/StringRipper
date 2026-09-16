// win_process.hpp - Win32 process enumeration and memory reading for URLRipper.
//
// Windows only. Kept behind _WIN32 so scan_core.hpp stays portable and the core
// can be tested elsewhere. This reads readable committed pages of a target
// process the current user is allowed to open. It never writes to another
// process, injects code, or opens the OS security core.
#pragma once
#ifdef _WIN32

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>

namespace ur {

struct ProcInfo {
    uint32_t pid = 0;
    std::string name;
    bool wow64 = false;          // 32-bit process on 64-bit Windows
    uint64_t workingSet = 0;
};

inline std::string narrow(const wchar_t* w) {
    if (!w) return {};
    int len = ::WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 1) return {};
    std::string s(static_cast<std::size_t>(len - 1), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), len, nullptr, nullptr);
    return s;
}

inline std::wstring widen(const std::string& s) {
    if (s.empty()) return {};
    int len = ::MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w(static_cast<std::size_t>(len), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), w.data(), len);
    return w;
}

// Names we never even try to open: opening them fails anyway and only writes a
// line to the security event log.
inline bool isSecuritySensitive(const std::string& name) {
    static const char* deny[] = {
        "lsass.exe", "lsaiso.exe", "csrss.exe", "smss.exe", "wininit.exe",
        "winlogon.exe", "services.exe", "MsMpEng.exe", "SecurityHealthService.exe",
    };
    for (const char* d : deny) {
        if (_stricmp(d, name.c_str()) == 0) return true;
    }
    return false;
}

inline std::vector<ProcInfo> enumerateProcesses() {
    std::vector<ProcInfo> out;
    HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    const DWORD self = ::GetCurrentProcessId();
    BOOL hostWow = FALSE;
    ::IsWow64Process(::GetCurrentProcess(), &hostWow);
    if (::Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == 0 || pe.th32ProcessID == 4) continue;
            if (pe.th32ProcessID == self) continue;
            ProcInfo pi;
            pi.pid = pe.th32ProcessID;
            pi.name = narrow(pe.szExeFile);
            if (isSecuritySensitive(pi.name)) continue;
            HANDLE h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pi.pid);
            if (!h) continue;   // cannot even query -> not usable, skip
            BOOL w = FALSE;
            ::IsWow64Process(h, &w);
            pi.wow64 = (w != FALSE);
            PROCESS_MEMORY_COUNTERS pmc{};
            if (::GetProcessMemoryInfo(h, &pmc, sizeof(pmc)))
                pi.workingSet = pmc.WorkingSetSize;
            ::CloseHandle(h);
            out.push_back(std::move(pi));
        } while (::Process32NextW(snap, &pe));
    }
    ::CloseHandle(snap);
    return out;
}

struct ReadLimits {
    uint64_t maxTotalBytes = 2ull * 1024 * 1024 * 1024;  // 2 GB cap
    std::size_t windowBytes = 4u * 1024 * 1024;          // read in 4 MB windows
};

// Walk readable committed regions of `pid`, calling sink(buffer, size, baseAddr)
// per window. cancel() may abort between windows. Returns false if the process
// could not be opened for reading.
inline bool readProcessMemory(
    uint32_t pid,
    const std::function<void(const uint8_t*, std::size_t, uint64_t)>& sink,
    const std::function<bool()>& cancel,
    const ReadLimits& limits = {}) {

    HANDLE h = ::OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return false;

    SYSTEM_INFO si{};
    ::GetSystemInfo(&si);
    uint64_t addr = reinterpret_cast<uint64_t>(si.lpMinimumApplicationAddress);
    const uint64_t maxAddr = reinterpret_cast<uint64_t>(si.lpMaximumApplicationAddress);

    std::vector<uint8_t> buf(limits.windowBytes);
    uint64_t total = 0;

    while (addr < maxAddr) {
        if (cancel && cancel()) break;
        MEMORY_BASIC_INFORMATION mbi{};
        if (::VirtualQueryEx(h, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == 0)
            break;
        uint64_t base = reinterpret_cast<uint64_t>(mbi.BaseAddress);
        uint64_t regionSize = mbi.RegionSize;
        bool readable = (mbi.State == MEM_COMMIT) &&
                        !(mbi.Protect & PAGE_GUARD) &&
                        !(mbi.Protect & PAGE_NOACCESS) &&
                        (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                                        PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                                        PAGE_EXECUTE_WRITECOPY));
        if (readable) {
            uint64_t off = 0;
            while (off < regionSize) {
                if (cancel && cancel()) break;
                if (total >= limits.maxTotalBytes) { ::CloseHandle(h); return true; }
                std::size_t want = static_cast<std::size_t>(
                    std::min<uint64_t>(limits.windowBytes, regionSize - off));
                SIZE_T got = 0;
                if (::ReadProcessMemory(h, reinterpret_cast<LPCVOID>(base + off),
                                        buf.data(), want, &got) && got > 0) {
                    sink(buf.data(), static_cast<std::size_t>(got), base + off);
                    total += got;
                }
                off += want;
            }
        }
        uint64_t next = base + regionSize;
        if (next <= addr) break;   // guard against no progress
        addr = next;
    }
    ::CloseHandle(h);
    return true;
}

// Is the current process elevated? (High-integrity targets need this.)
inline bool isElevated() {
    HANDLE token = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION el{};
    DWORD len = 0;
    bool res = ::GetTokenInformation(token, TokenElevation, &el, sizeof(el), &len) && el.TokenIsElevated;
    ::CloseHandle(token);
    return res;
}

} // namespace ur
#endif // _WIN32
