/* multi-threaded scan: one reader thread (a process handle is single-reader)
   fans windows out to a Detector pool. reader = FXChainPlayer's IMemoryReader. */
#pragma once

#include "scan_core.hpp"
#if __has_include("audio/memory_ripper.h")
#include "audio/memory_ripper.h"
#define SR_HAVE_RIPPER 1
#endif

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <filesystem>
#include <fstream>
#include <functional>
#include <exception>
#include <limits>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace ur {

struct DriverLimits {
    uint64_t    maxBytes = 2ull * 1024 * 1024 * 1024;
    std::size_t window   = 1u * 1024 * 1024;
    std::size_t overlap  = 64u * 1024;
    unsigned    threads  = 0;
    bool        skipSystemImages = false;
    uint64_t    rangeStart = 0, rangeEnd = 0; // end is exclusive; zero means unbounded
};

inline unsigned chooseThreads(unsigned req) {
    if (req) return req;
    unsigned hw = std::thread::hardware_concurrency();
    return std::min(16u, hw > 3 ? hw - 2 : 1u);
}

struct ScanProgress {
    std::atomic<uint64_t> total{0}, completed{0}, skipped{0};
    std::atomic<bool> planning{true}, merging{false};
    void reset() { total = 0; completed = 0; skipped = 0; planning = true; merging = false; }
    double percent() const {
        const auto n = total.load();
        if (!n) return 0.0;
        const auto processed = std::min(n, completed.load() + skipped.load());
        return 100.0 * static_cast<double>(processed) / static_cast<double>(n);
    }
};

class ScanGate {
public:
    void setPaused(bool paused) { paused_.store(paused); cv_.notify_all(); }
    bool paused() const { return paused_.load(); }
    void wait(const std::function<bool()>& cancelled) {
        if (!paused_) return;
        std::unique_lock lk(m_);
        while (paused_ && !(cancelled && cancelled())) cv_.wait_for(lk, std::chrono::milliseconds(100));
    }
private:
    std::atomic<bool> paused_{false};
    std::mutex m_;
    std::condition_variable cv_;
};

class ScanPool {
public:
    ScanPool(const Detector& det, unsigned threads, std::size_t maxInFlightBytes,
             ScanProgress* progress = nullptr, std::function<bool()> cancel = {},
             std::function<void()> pause = {})
        : det_(det), maxInFlight_(maxInFlightBytes), progress_(progress),
          cancel_(std::move(cancel)), pause_(std::move(pause)) {
        unsigned n = chooseThreads(threads);
        sinks_.resize(n);
        try {
            for (unsigned i = 0; i < n; ++i) workers_.emplace_back([this, i] { worker(i); });
        } catch (...) { stop(); throw; }
    }

    ~ScanPool() { stop(); }
    bool cancelled() const { return cancel_ && cancel_(); }

    void submit(std::vector<uint8_t>&& buf, const std::string& source, uint64_t freshBytes = 0,
                uint64_t origin = 0, bool knownOffset = false) {
        std::size_t sz = buf.size();
        std::unique_lock lk(m_);
        drained_.wait(lk, [&] { return failure_ || !inFlightBytes_ ||
            (sz <= maxInFlight_ && inFlightBytes_ <= maxInFlight_ - sz); });
        if (failure_) std::rethrow_exception(failure_);
        if (cancelled()) return;
        q_.push_back(Task{std::move(buf), source, freshBytes ? freshBytes : sz, origin, knownOffset});
        inFlightBytes_ += sz;
        cv_.notify_one();
    }

    std::vector<Group> finish() {
        stop();
        if (failure_) std::rethrow_exception(failure_);
        if (progress_) progress_->merging = true;
        return mergeSinks(sinks_);
    }

private:
    struct Task {
        std::vector<uint8_t> buf; std::string source;
        uint64_t freshBytes, origin; bool knownOffset;
    };

    void stop() {
        { std::unique_lock lk(m_); done_ = true; }
        cv_.notify_all();
        for (auto& t : workers_) if (t.joinable()) t.join();
    }

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
            try {
                if (!cancelled()) {
                    if (pause_) pause_();
                    if (!cancelled()) {
                        det_.scan(task.buf.data(), task.buf.size(), task.source, sinks_[idx],
                                  task.origin, task.knownOffset);
                        if (progress_) progress_->completed += task.freshBytes;
                    }
                }
            } catch (...) {
                std::unique_lock lk(m_);
                if (!failure_) failure_ = std::current_exception();
            }
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
    ScanProgress* progress_;
    std::function<bool()> cancel_;
    std::function<void()> pause_;
    std::exception_ptr failure_;
};

#ifdef SR_HAVE_RIPPER
inline uint64_t scanReaderInto(fxchain::IMemoryReader& reader, ScanPool& pool,
                               const std::string& sourceName, const DriverLimits& lim,
                               const std::function<bool(uint64_t)>& progress = {}, ScanProgress* state = nullptr,
                               const std::function<void()>& pause = {}) {
    const uint64_t maxAddr = reader.maximumAddress();
    uint64_t addr = std::max(reader.minimumAddress(), lim.rangeStart);
    const uint64_t rangeEnd = lim.rangeEnd ? std::min(maxAddr, lim.rangeEnd) : maxAddr;
    uint64_t total = 0;
    std::vector<fxchain::RipMemoryRegion> regions;
    uint64_t planned = 0;
    while (addr < rangeEnd && planned < lim.maxBytes && !pool.cancelled()) {
        fxchain::RipMemoryRegion r{};
        if (!reader.query(addr, r)) break;
        uint64_t next = r.base + r.size;
        if (next <= addr) break;
        if (r.committed && r.readable && !r.guarded && !(lim.skipSystemImages && r.systemImage)) {
            r.base = std::max(r.base, addr);
            r.size = std::min(next, rangeEnd) - r.base;
            r.size = std::min(r.size, lim.maxBytes - planned);
            planned += r.size; regions.push_back(r);
        }
        addr = next;
    }
    if (state) { state->total = planned; state->planning = false; }
    std::vector<uint8_t> chunk(lim.window);
    for (const auto& region : regions) {
        if (pool.cancelled()) break;
        {
            std::vector<uint8_t> tail;
            uint64_t off = 0;
            while (off < region.size && total < lim.maxBytes) {
                if (pause) pause();
                if (pool.cancelled()) return total;
                std::size_t want = static_cast<std::size_t>(
                    std::min<uint64_t>(lim.window, region.size - off));
                fxchain::RipReadResult r = reader.read(region.base + off, chunk.data(), want);
                if (r.bytesRead == 0) {
                    if (state) state->skipped += region.size - off;
                    break;
                }
                const auto prefix = tail.size();
                std::vector<uint8_t> buf;
                buf.reserve(tail.size() + r.bytesRead);
                buf.insert(buf.end(), tail.begin(), tail.end());
                buf.insert(buf.end(), chunk.begin(), chunk.begin() + r.bytesRead);
                std::size_t keep = std::min<std::size_t>(lim.overlap, buf.size());
                tail.assign(buf.end() - keep, buf.end());
                total += r.bytesRead;
                pool.submit(std::move(buf), sourceName, r.bytesRead,
                            region.base + off - prefix, true);
                if (progress && !progress(total)) return total;
                off += r.bytesRead;
            }
        }
    }
    return total;
}
#endif // SR_HAVE_RIPPER

inline bool scanFileInto(const std::filesystem::path& path, ScanPool& pool, const DriverLimits& lim,
                         const std::function<void(uint64_t)>& progress = {},
                         uint64_t byteLimit = std::numeric_limits<uint64_t>::max(),
                         const std::function<void()>& pause = {}) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    if (lim.rangeEnd && lim.rangeEnd <= lim.rangeStart) return false;
    if (lim.rangeStart) f.seekg(static_cast<std::streamoff>(lim.rangeStart));
    if (!f) return false;
    const std::string label = path.string();
    std::vector<uint8_t> chunk(lim.window);
    std::vector<uint8_t> tail;
    uint64_t done = 0;
    const auto rangeLimit = lim.rangeEnd ? lim.rangeEnd - lim.rangeStart :
                            std::numeric_limits<uint64_t>::max();
    byteLimit = std::min(byteLimit, rangeLimit);
    while (done < byteLimit) {
        if (pause) pause();
        if (pool.cancelled()) return true;
        const auto want = std::min<uint64_t>(lim.window, byteLimit - done);
        f.read(reinterpret_cast<char*>(chunk.data()), static_cast<std::streamsize>(want));
        std::streamsize got = f.gcount();
        if (got <= 0) break;
        done += static_cast<uint64_t>(got);
        if (progress) progress(done);
        const auto prefix = tail.size();
        std::vector<uint8_t> buf;
        buf.reserve(tail.size() + static_cast<std::size_t>(got));
        buf.insert(buf.end(), tail.begin(), tail.end());
        buf.insert(buf.end(), chunk.begin(), chunk.begin() + got);
        std::size_t keep = std::min<std::size_t>(lim.overlap, buf.size());
        tail.assign(buf.end() - keep, buf.end());
        pool.submit(std::move(buf), label, static_cast<uint64_t>(got),
                    lim.rangeStart + done - static_cast<uint64_t>(got) - prefix, true);
        if (!f) break;
    }
    return !f.bad();
}

} // namespace ur
