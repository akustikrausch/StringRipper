#pragma once

#include "scan_driver.hpp"
#include "audio/rip_backend.h"
#include <functional>
#include <string>

namespace ur {

inline std::vector<Group> scanProcess(const Detector& detector, uint32_t pid,
                                      const std::function<bool()>& cancel,
                                      bool& accessDenied, bool& needsElevation,
                                      ScanProgress* progress = nullptr,
                                      const DriverLimits& limits = {},
                                      const std::function<void()>& pause = {}) {
    accessDenied = false;
    needsElevation = false;
    std::string name = fxchain::ripBackend().processName(pid);
    if (name.empty()) name = "pid" + std::to_string(pid);
    ScanPool pool(detector, 0, 256u * 1024 * 1024, progress, cancel, pause);
    fxchain::RipStats stats;
    fxchain::RipTargetInfo info;
    bool opened = fxchain::ripBackend().withReader(pid, stats, info,
        [&](fxchain::IMemoryReader& reader) {
            scanReaderInto(reader, pool, name, limits, {}, progress, pause);
        });
    auto groups = pool.finish();
    if (!opened) {
        accessDenied = true;
        needsElevation = (stats.access == fxchain::RipAccess::NeedsElevation);
    }
    return groups;
}

} // namespace ur
