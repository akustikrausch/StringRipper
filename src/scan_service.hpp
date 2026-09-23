#pragma once

#include "file_read.hpp"
#include "scan_driver.hpp"
#include <algorithm>
#include <filesystem>
#include <functional>
#include <vector>

namespace ur {

// Application use case shared by Win32 UI/CLI and the portable CLI.
inline std::vector<Group> scanPaths(const Detector& detector,
                                    const std::vector<std::filesystem::path>& inputs,
                                    bool* denied = nullptr,
                                    ScanProgress* progress = nullptr,
                                    const std::function<bool()>& cancel = {},
                                    const FileSelection& selection = {},
                                    const std::function<void()>& pause = {}) {
    DriverLimits limits;
    limits.rangeStart = selection.rangeStart;
    limits.rangeEnd = selection.rangeEnd;
    ScanPool pool(detector, 0, 256u * 1024 * 1024, progress, cancel, pause);
    auto files = expandInputs(inputs, 0, cancel, selection);
    uint64_t planned = 0;
    std::size_t bad = 0;
    std::vector<uint64_t> sizes;
    sizes.reserve(files.size());
    for (const auto& file : files) {
        if (pool.cancelled()) break;
        std::error_code error;
        const auto size = std::filesystem::file_size(file, error);
        if (error) ++bad;
        uint64_t end = error ? 0 : (selection.rangeEnd ? std::min<uint64_t>(size, selection.rangeEnd) : size);
        sizes.push_back(end > selection.rangeStart ? end - selection.rangeStart : 0);
        planned += sizes.back();
    }
    if (progress) { progress->total = planned; progress->planning = false; }
    for (std::size_t i = 0; i < sizes.size() && !pool.cancelled(); ++i) {
        uint64_t read = 0;
        if (!scanFileInto(files[i], pool, limits, [&](uint64_t n) { read = n; }, sizes[i], pause))
            ++bad;
        if (progress && read < sizes[i] && !pool.cancelled())
            progress->skipped += sizes[i] - read;
    }
    if (denied) *denied = bad > 0 || (files.empty() && !inputs.empty());
    return pool.finish();
}

} // namespace ur
