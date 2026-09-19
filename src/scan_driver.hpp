/* multi-threaded scan: one reader thread (a process handle is single-reader)
   fans windows out to a Detector pool. reader = FXChainPlayer's IMemoryReader. */
#pragma once

#include "scan_core.hpp"
#if __has_include("audio/memory_ripper.h")
#include "audio/memory_ripper.h"
#define SR_HAVE_RIPPER 1
#endif

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <filesystem>
#include <fstream>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace ur {

struct DriverLimits {
    uint64_t    maxBytes = 2ull * 1024 * 1024 * 1024;
    std::size_t window   = 8u * 1024 * 1024;
    std::size_t overlap  = 64u * 1024;
    unsigned    threads  = 0;
    bool        skipSystemImages = false;
};

inline unsigned chooseThreads(unsigned req) {
    if (req) return req;
    unsigned hw = std::thread::hardware_concurrency();
    return hw > 3 ? hw - 2 : 1u;
}

class ScanPool {
public:
    ScanPool(const Detector& det, unsigned threads, std::size_t maxInFlightBytes)
        : det_(det), maxInFlight_(maxInFlightBytes) {
        unsigned n = chooseThreads(threads);
        sinks_.resize(n);
        for (unsigned i = 0; i < n; ++i)
            workers_.emplace_back([this, i] { worker(i); });
    }

    void submit(std::vector<uint8_t>&& buf, const std::string& source) {
        std::size_t sz = buf.size();
        std::unique_lock lk(m_);
        drained_.wait(lk, [&] { return inFlightBytes_ <= maxInFlight_; });
        inFlightBytes_ += sz;
        q_.push_back(Task{std::move(buf), source});
        cv_.notify_one();
    }

    std::vector<Group> finish() {
        { std::unique_lock lk(m_); done_ = true; }
        cv_.notify_all();
        for (auto& t : workers_) t.join();
        return mergeSinks(sinks_);
    }

private:
    struct Task { std::vector<uint8_t> buf; std::string source; };

    void worker(unsigned idx) {
        for (;;) {
            Task task;
            {
                std::unique_lock lk(m_);
                cv_.wait(lk, [&] { return done_ || !q_.empty(); });
                if (q_.empty()) { if (done_) return; else continue; }
                task = std::move(q_.front());
                q_.pop_front();
            }
            det_.scan(task.buf.data(), task.buf.size(), task.source, sinks_[idx]);
            {
                std::unique_lock lk(m_);
                inFlightBytes_ -= task.buf.size();
            }
            drained_.notify_all();
        }
    }

    const Detector& det_;
    std::vector<Sink> sinks_;
    std::vector<std::thread> workers_;
    std::mutex m_;
    std::condition_variable cv_, drained_;
    std::deque<Task> q_;
    bool done_ = false;
    std::size_t inFlightBytes_ = 0;
    std::size_t maxInFlight_;
};

#ifdef SR_HAVE_RIPPER
inline uint64_t scanReaderInto(fxchain::IMemoryReader& reader, ScanPool& pool,
                               const std::string& sourceName, const DriverLimits& lim,
                               const std::function<bool(uint64_t)>& progress = {}) {
    const uint64_t maxAddr = reader.maximumAddress();
    uint64_t addr = reader.minimumAddress();
    uint64_t total = 0;
    std::vector<uint8_t> chunk(lim.window);
    while (addr < maxAddr && total < lim.maxBytes) {
        fxchain::RipMemoryRegion region{};
        if (!reader.query(addr, region)) break;
        uint64_t next = region.base + region.size;
        if (next <= addr) break;
        const bool eligible = region.committed && region.readable && !region.guarded &&
                              !(lim.skipSystemImages && region.systemImage);
        if (eligible) {
            std::vector<uint8_t> tail;
            uint64_t off = 0;
            while (off < region.size && total < lim.maxBytes) {
                std::size_t want = static_cast<std::size_t>(
                    std::min<uint64_t>(lim.window, region.size - off));
                fxchain::RipReadResult r = reader.read(region.base + off, chunk.data(), want);
                if (r.bytesRead == 0) break;
                std::vector<uint8_t> buf;
                buf.reserve(tail.size() + r.bytesRead);
                buf.insert(buf.end(), tail.begin(), tail.end());
                buf.insert(buf.end(), chunk.begin(), chunk.begin() + r.bytesRead);
                std::size_t keep = std::min<std::size_t>(lim.overlap, r.bytesRead);
                tail.assign(chunk.begin() + (r.bytesRead - keep), chunk.begin() + r.bytesRead);
                char lbl[40];
                std::snprintf(lbl, sizeof(lbl), "+0x%llx", (unsigned long long)(region.base + off));
                total += r.bytesRead;
                pool.submit(std::move(buf), sourceName + lbl);
                if (progress && !progress(total)) return total;
                off += r.bytesRead;
            }
        }
        addr = next;
    }
    return total;
}
#endif // SR_HAVE_RIPPER

inline bool scanFileInto(const std::filesystem::path& path, ScanPool& pool, const DriverLimits& lim,
                         const std::function<void(uint64_t)>& progress = {}) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    const std::string label = path.string();
    std::vector<uint8_t> chunk(lim.window);
    std::vector<uint8_t> tail;
    uint64_t done = 0;
    for (;;) {
        f.read(reinterpret_cast<char*>(chunk.data()), static_cast<std::streamsize>(lim.window));
        std::streamsize got = f.gcount();
        if (got <= 0) break;
        done += static_cast<uint64_t>(got);
        if (progress) progress(done);
        std::vector<uint8_t> buf;
        buf.reserve(tail.size() + static_cast<std::size_t>(got));
        buf.insert(buf.end(), tail.begin(), tail.end());
        buf.insert(buf.end(), chunk.begin(), chunk.begin() + got);
        std::size_t keep = std::min<std::size_t>(lim.overlap, static_cast<std::size_t>(got));
        tail.assign(chunk.begin() + (static_cast<std::size_t>(got) - keep), chunk.begin() + got);
        pool.submit(std::move(buf), label);
        if (!f) break;
    }
    return true;
}

} // namespace ur
