// test_driver.cpp - exercises the multi-threaded scan driver over a MOCK
// IMemoryReader, so the process-scan path is verified without opening any real
// process. Needs the FXChainPlayer include path (for IMemoryReader). Build:
//   cl /std:c++20 /EHsc /I <fxcp>/src /I src tests\test_driver.cpp
#include "scan_driver.hpp"
#include "audio/rip_backend.h"

#include <cstdio>
#include <cstring>
#include <vector>
#include <fstream>
#include <chrono>

namespace {
struct MockReader : fxchain::IMemoryReader {
    std::vector<uint8_t> mem;
    uint64_t base = 0x100000;
    bool readFails = false;
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
        if (readFails) return {0, false};
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
    ur::ScanProgress state;
    ur::ScanPool pool(det, 0, 128u * 1024 * 1024, &state);
    uint64_t bytes = ur::scanReaderInto(rd, pool, "mock", lim, {}, &state);
    auto groups = pool.finish();
    if (state.total != rd.mem.size() || state.completed != bytes || state.skipped || state.planning ||
        !state.merging || state.percent() != 100.0) {
        std::puts("FAIL: progress counts completed fresh bytes, not overlaps"); ++fail;
    }
    {
        ur::DriverLimits small; small.maxBytes = 12345; small.window = 4096; small.overlap = 128;
        ur::ScanProgress capped;
        ur::ScanPool p(det, 2, 8192, &capped);
        auto n = ur::scanReaderInto(rd, p, "limited", small, {}, &capped);
        p.finish();
        if (n != 12345 || capped.total != n || capped.completed != n) {
            std::puts("FAIL: memory limit and progress must be exact"); ++fail;
        }
    }
    {
        bool cancel = true;
        ur::ScanProgress cancelled;
        ur::ScanPool p(det, 2, 8192, &cancelled, [&] { return cancel; });
        auto n = ur::scanReaderInto(rd, p, "cancelled", lim, {}, &cancelled);
        p.finish();
        if (n || cancelled.completed) { std::puts("FAIL: pre-cancelled scan did work"); ++fail; }
    }

    std::printf("scanned %llu bytes, %zu groups, %zu findings\n",
                (unsigned long long)bytes, groups.size(), ur::countFindings(groups));
    bool found = false;
    {
        MockReader gone; gone.mem.resize(8192); gone.readFails = true;
        ur::ScanProgress changed;
        ur::ScanPool p(det, 2, 8192, &changed);
        ur::scanReaderInto(gone, p, "gone", lim, {}, &changed);
        p.finish();
        if (changed.total != 8192 || changed.completed != 0 || changed.skipped != 8192) {
            std::puts("FAIL: unreadable memory must not count as scanned"); ++fail;
        }
    }
    {
        auto path = std::filesystem::temp_directory_path() /
            ("stringripper-file-test-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        { std::ofstream f(path, std::ios::binary); f.write((const char*)rd.mem.data(), 12345); }
        ur::ScanProgress fileProgress;
        ur::ScanPool p(det, 2, 8192, &fileProgress);
        ur::DriverLimits small; small.window = 4096; small.overlap = 128;
        if (!ur::scanFileInto(path, p, small)) ++fail;
        p.finish();
        if (fileProgress.completed != 12345) { std::puts("FAIL: file progress includes overlap"); ++fail; }
        ur::ScanProgress cancelled;
        ur::ScanPool q(det, 2, 8192, &cancelled, [] { return true; });
        ur::scanFileInto(path, q, small); q.finish();
        if (cancelled.completed) { std::puts("FAIL: cancelled file was scanned"); ++fail; }
        ur::ScanProgress snapshot;
        ur::ScanPool bounded(det, 2, 8192, &snapshot);
        ur::scanFileInto(path, bounded, small, {}, 5000); bounded.finish();
        if (snapshot.completed != 5000) { std::puts("FAIL: file size snapshot exceeded"); ++fail; }
        std::filesystem::remove(path);
    }
    {
        // one region, two names: each half keeps its own, nothing is read twice,
        // and a labeler that gives no end falls back to the whole region
        MockReader two; two.mem.resize(0x6000);
        auto at = [&](std::size_t o, const char* s) { std::memcpy(two.mem.data() + o, s, std::strlen(s)); };
        at(0x100, "https://first.akustikrausch.de/a");
        at(0x3100, "https://second.akustikrausch.de/b");
        const uint64_t cut = two.base + 0x3000;
        ur::DriverLimits small; small.window = 4096; small.overlap = 128;
        ur::ScanProgress split;
        ur::ScanPool p(det, 2, 8192, &split);
        auto n = ur::scanReaderInto(two, p, "mock", small, {}, &split, {}, [&](uint64_t a, uint64_t& end) {
            if (a < cut) { end = cut; return std::string("first"); }
            return std::string("second");
        });
        auto halves = p.finish();
        std::string first, second;
        for (const auto& g : halves) for (const auto& f : g.items) {
            if (f.value.find("first.") != std::string::npos) first = f.source;
            if (f.value.find("second.") != std::string::npos) second = f.source;
        }
        if (n != two.mem.size() || split.total != n || split.completed != n ||
            first != "mock [first]" || second != "mock [second]") {
            std::printf("FAIL: split labels (%llu bytes, '%s', '%s')\n", (unsigned long long)n, first.c_str(), second.c_str()); ++fail;
        }
        ur::ScanProgress stuck;
        ur::ScanPool q(det, 2, 8192, &stuck);
        auto m = ur::scanReaderInto(two, q, "mock", small, {}, &stuck, {},
                                    [](uint64_t a, uint64_t& end) { end = a; return std::string(); });
        auto whole = q.finish();
        if (m != two.mem.size() || ur::countFindings(whole) != 2 || whole.front().items.front().source != "mock") {
            std::puts("FAIL: a label without an end must cover the rest of the region"); ++fail;
        }
    }
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
