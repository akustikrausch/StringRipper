#pragma once

#include "scan_driver.hpp"
#include "audio/rip_backend.h"
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <functional>
#include <string>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace ur {

/* names the memory an address sits in: "xul.dll .rdata", "mapped foo.dat",
   "stack", "heap" or "private", and where that name stops holding (section
   end, else region end). Stacks come from each thread's TEB, heaps from the
   PEB heap list (their base segments; the rest of private memory stays
   "private"). Own handle, so it works whatever the reader holds. */
class RegionLabeler {
public:
    explicit RegionLabeler(uint32_t pid) {
        h_ = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!h_) return;
        BOOL wow = FALSE;
        IsWow64Process(h_, &wow);
        using NtQuery = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        HMODULE nt = GetModuleHandleW(L"ntdll.dll");
        auto thread = reinterpret_cast<NtQuery>(GetProcAddress(nt, "NtQueryInformationThread"));
        auto process = reinterpret_cast<NtQuery>(GetProcAddress(nt, "NtQueryInformationProcess"));
        struct { LONG exit; PVOID teb; PVOID ids[2]; ULONG_PTR affinity; LONG priority, base; } tbi{};
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap != INVALID_HANDLE_VALUE && thread) {
            THREADENTRY32 te{sizeof(te)};
            for (BOOL ok = Thread32First(snap, &te); ok; ok = Thread32Next(snap, &te)) {
                if (te.th32OwnerProcessID != pid) continue;
                HANDLE th = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                if (!th) continue;
                if (thread(th, 0, &tbi, sizeof(tbi), nullptr) == 0) {
                    const uint64_t teb = reinterpret_cast<uint64_t>(tbi.teb);
                    uint64_t tib[3];
                    if (read(teb, tib, sizeof(tib))) stacks_.push_back({tib[2], tib[1]});
                    uint32_t tib32[3];
                    if (wow && read(teb + 0x2000, tib32, sizeof(tib32))) stacks_.push_back({tib32[2], tib32[1]});
                }
                CloseHandle(th);
            }
        }
        if (snap != INVALID_HANDLE_VALUE) CloseHandle(snap);
        if (!process) return;
        struct { PVOID r1; PVOID peb; PVOID r2[2]; ULONG_PTR pid; PVOID r3; } pbi{};
        uint32_t count = 0;
        if (process(h_, 0, &pbi, sizeof(pbi), nullptr) == 0) {
            const uint64_t peb = reinterpret_cast<uint64_t>(pbi.peb);
            uint64_t list = 0;
            if (read(peb + 0xE8, &count, 4) && read(peb + 0xF0, &list, 8) && count && count < 4096) {
                std::vector<uint64_t> hs(count);
                if (read(list, hs.data(), count * 8)) heaps_.insert(hs.begin(), hs.end());
            }
        }
        ULONG_PTR peb32 = 0;
        if (wow && process(h_, 26, &peb32, sizeof(peb32), nullptr) == 0 && peb32) {
            uint32_t list = 0;
            if (read(peb32 + 0x88, &count, 4) && read(peb32 + 0x90, &list, 4) && count && count < 4096) {
                std::vector<uint32_t> hs(count);
                if (read(list, hs.data(), count * 4)) heaps_.insert(hs.begin(), hs.end());
            }
        }
    }
    ~RegionLabeler() { if (h_) CloseHandle(h_); }
    RegionLabeler(const RegionLabeler&) = delete;
    RegionLabeler& operator=(const RegionLabeler&) = delete;

    std::string operator()(uint64_t address, uint64_t& spanEnd) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!h_ || !VirtualQueryEx(h_, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi))) return {};
        const uint64_t base = reinterpret_cast<uint64_t>(mbi.AllocationBase);
        spanEnd = reinterpret_cast<uint64_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (mbi.Type == MEM_IMAGE) {
            const Module& m = module(base);
            const uint64_t rva = address - base;
            uint64_t next = UINT64_MAX;
            for (const auto& [name, lo, hi] : m.sections) {
                if (rva >= lo && rva < hi) { spanEnd = std::min(spanEnd, base + hi); return m.name + " " + name; }
                if (lo > rva) next = std::min<uint64_t>(next, lo);
            }
            if (next != UINT64_MAX) spanEnd = std::min(spanEnd, base + next);
            return m.name;
        }
        if (mbi.Type == MEM_MAPPED) {
            auto it = mapped_.find(base);
            if (it == mapped_.end()) it = mapped_.emplace(base, fileName(base)).first;
            return it->second.empty() ? "mapped" : "mapped " + it->second;
        }
        for (const auto& [lo, hi] : stacks_) if (address >= lo && address < hi) return "stack";
        return heaps_.count(base) ? "heap" : "private";
    }

private:
    struct Module { std::string name; std::vector<std::tuple<std::string, uint32_t, uint32_t>> sections; };

    bool read(uint64_t at, void* out, std::size_t n) const {
        SIZE_T got = 0;
        return ReadProcessMemory(h_, reinterpret_cast<LPCVOID>(at), out, n, &got) && got == n;
    }
    std::string fileName(uint64_t base) const {
        wchar_t path[1024];
        DWORD n = GetMappedFileNameW(h_, reinterpret_cast<LPVOID>(base), path, 1024);
        if (!n) return {};
        std::wstring w(path, n);
        auto slash = w.find_last_of(L"\\/");
        if (slash != std::wstring::npos) w.erase(0, slash + 1);
        int len = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), int(w.size()), nullptr, 0, nullptr, nullptr);
        std::string out(std::size_t(len), '\0');
        WideCharToMultiByte(CP_UTF8, 0, w.c_str(), int(w.size()), out.data(), len, nullptr, nullptr);
        return out;
    }
    const Module& module(uint64_t base) {
        auto it = modules_.find(base);
        if (it != modules_.end()) return it->second;
        Module m;
        m.name = fileName(base);
        if (m.name.empty()) m.name = "image";
        uint8_t h[4096];
        uint32_t pe = 0;
        if (read(base, h, sizeof(h)) && h[0] == 'M' && h[1] == 'Z') std::memcpy(&pe, h + 0x3C, 4);
        if (pe && pe + 64 < sizeof(h) && std::memcmp(h + pe, "PE\0\0", 4) == 0) {
            uint16_t count, opt;
            uint32_t align;
            std::memcpy(&count, h + pe + 6, 2); std::memcpy(&opt, h + pe + 20, 2); std::memcpy(&align, h + pe + 56, 4);
            if (!align || (align & (align - 1))) align = 0x1000;
            for (std::size_t s = pe + 24 + opt, i = 0; i < count && s + 40 <= sizeof(h); ++i, s += 40) {
                char name[9] = {};
                uint32_t size, va;
                std::memcpy(name, h + s, 8); std::memcpy(&size, h + s + 8, 4); std::memcpy(&va, h + s + 12, 4);
                if (!size) std::memcpy(&size, h + s + 16, 4);
                m.sections.emplace_back(name, va, (va + size + align - 1) & ~(align - 1));
            }
        }
        return modules_.emplace(base, std::move(m)).first->second;
    }

    HANDLE h_ = nullptr;
    std::vector<std::pair<uint64_t, uint64_t>> stacks_;
    std::unordered_set<uint64_t> heaps_;
    std::unordered_map<uint64_t, Module> modules_;
    std::unordered_map<uint64_t, std::string> mapped_;
};

struct ProcessScan {
    std::vector<Group> groups;
    std::size_t opened = 0, denied = 0;
    bool needsElevation = false;
};

/* several processes into one result. The source names the process ("app.exe",
   or "app.exe (pid 42)" with pidInSource) and the region each hit came from.
   With more than one target, every one is planned first so the percent covers
   the whole job; maxBytes still caps each process on its own. */
inline ProcessScan scanProcesses(const Detector& detector, const std::vector<uint32_t>& pids, bool pidInSource,
                                 const std::function<bool()>& cancel, ScanProgress* progress = nullptr,
                                 const DriverLimits& limits = {}, const std::function<void()>& pause = {}) {
    ProcessScan out;
    ScanPool pool(detector, 0, 256u * 1024 * 1024, progress, cancel, pause);
    const bool shared = pids.size() > 1;
    if (progress && shared) {
        uint64_t total = 0;
        for (uint32_t pid : pids) {
            fxchain::RipStats stats; fxchain::RipTargetInfo info;
            fxchain::ripBackend().withReader(pid, stats, info, [&](fxchain::IMemoryReader& reader) {
                uint64_t planned = 0; planRegions(reader, limits, planned, cancel); total += planned;
            });
        }
        progress->total = total; progress->planning = false;
    }
    for (uint32_t pid : pids) {
        if (cancel && cancel()) break;
        std::string name = fxchain::ripBackend().processName(pid);
        if (name.empty()) name = "pid" + std::to_string(pid);
        if (pidInSource) name += " (pid " + std::to_string(pid) + ")";
        RegionLabeler label(pid);
        fxchain::RipStats stats; fxchain::RipTargetInfo info;
        const bool opened = fxchain::ripBackend().withReader(pid, stats, info, [&](fxchain::IMemoryReader& reader) {
            scanReaderInto(reader, pool, name, limits, {}, progress, pause,
                           [&label](uint64_t a, uint64_t& end) { return label(a, end); }, shared);
        });
        if (opened) ++out.opened;
        else { ++out.denied; out.needsElevation |= stats.access == fxchain::RipAccess::NeedsElevation; }
    }
    out.groups = pool.finish();
    return out;
}

inline std::vector<Group> scanProcess(const Detector& detector, uint32_t pid,
                                      const std::function<bool()>& cancel,
                                      bool& accessDenied, bool& needsElevation,
                                      ScanProgress* progress = nullptr,
                                      const DriverLimits& limits = {},
                                      const std::function<void()>& pause = {}) {
    auto scan = scanProcesses(detector, {pid}, false, cancel, progress, limits, pause);
    accessDenied = scan.denied != 0;
    needsElevation = scan.needsElevation;
    return std::move(scan.groups);
}

} // namespace ur
