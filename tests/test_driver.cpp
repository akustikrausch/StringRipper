// test_driver.cpp - exercises the multi-threaded scan driver over a MOCK
// IMemoryReader, so the process-scan path is verified without opening any real
// process. Needs the FXChainPlayer include path (for IMemoryReader). Build:
//   cl /std:c++20 /EHsc /I <fxcp>/src /I src tests\test_driver.cpp
#include "scan_driver.hpp"
#include "audio/rip_backend.h"

#include <cstdio>
#include <cstring>
#include <vector>

namespace {
struct MockReader : fxchain::IMemoryReader {
    std::vector<uint8_t> mem;
    uint64_t base = 0x100000;
    uint64_t minimumAddress() const override { return base; }
    uint64_t maximumAddress() const override { return base + mem.size(); }
    bool query(uint64_t a, fxchain::RipMemoryRegion& r) override {
        if (a < base || a >= base + mem.size()) return false;
        r.base = base; r.size = mem.size();
        r.committed = true; r.readable = true;
        r.guarded = false; r.image = false; r.systemImage = false;
        return true;
    }
    fxchain::RipReadResult read(uint64_t a, uint8_t* d, size_t n) override {
        if (a < base) return {0, false};
        size_t off = static_cast<size_t>(a - base);
        if (off >= mem.size()) return {0, false};
        size_t k = std::min(n, mem.size() - off);
        std::memcpy(d, mem.data() + off, k);
        return {k, k == n};
    }
};

void put(std::vector<uint8_t>& m, const char* s) {
    m.push_back(0);
    while (*s) m.push_back((uint8_t)*s++);
    m.push_back(0);
}
} // namespace

int main() {
    int fail = 0;
    MockReader rd;
    // ~40 MB so the driver produces several windows across the worker pool.
    for (int i = 0; i < 4000; ++i) {
        for (int j = 0; j < 100; ++j) rd.mem.insert(rd.mem.end(), 64, 0x00);
        put(rd.mem, (std::string("https://host") + std::to_string(i % 500) + ".example.com/p") .c_str());
    }

    ur::Options o; // URL mode
    ur::Detector det(o);
    ur::DriverLimits lim;
    ur::ScanPool pool(det, 0, 128u * 1024 * 1024);
    uint64_t bytes = ur::scanReaderInto(rd, pool, "mock", lim, {});
    auto groups = pool.finish();

    std::printf("scanned %llu bytes, %zu groups, %zu findings\n",
                (unsigned long long)bytes, groups.size(), ur::countFindings(groups));
    bool found = false;
    for (auto& g : groups) if (g.name == "host0.example.com") found = true;
    if (!found) { std::printf("FAIL: expected domain not found\n"); ++fail; }
    if (groups.size() != 500) { std::printf("FAIL: expected 500 domains, got %zu\n", groups.size()); ++fail; }
    // sorted Z to A
    if (groups.size() >= 2 && !(groups.front().name >= groups.back().name)) {
        std::printf("FAIL: not sorted descending\n"); ++fail;
    }
    std::printf(fail ? "\n%d FAILURE(S)\n" : "\nALL PASS\n", fail);
    return fail ? 1 : 0;
}
