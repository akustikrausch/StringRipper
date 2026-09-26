#pragma once

#include "scan_core.hpp"
#include <filesystem>
#include <iomanip>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace ur {

struct FileSelection {
    std::string include = "*";
    std::string exclude;
    uint64_t minSize = 0, maxSize = 0;
    int64_t modifiedAfter = 0, modifiedBefore = 0;
    uint64_t rangeStart = 0, rangeEnd = 0;
};

inline std::string selectionContext(const FileSelection& f) {
    return std::to_string(f.include.size()) + ":" + f.include +
        std::to_string(f.exclude.size()) + ":" + f.exclude + ":" +
        std::to_string(f.minSize) + ":" + std::to_string(f.maxSize) + ":" +
        std::to_string(f.modifiedAfter) + ":" + std::to_string(f.modifiedBefore) + ":" +
        std::to_string(f.rangeStart) + ":" + std::to_string(f.rangeEnd);
}

struct ScanJob {
    std::string name;
    std::vector<std::filesystem::path> sources;
    uint32_t pid = 0;
    Options options;
    FileSelection files;
    unsigned monitorSeconds = 0;
};

struct Session {
    int64_t id = 0;
    std::string name, source, created;
    std::vector<Group> groups;
};

struct SessionDelta {
    std::vector<Group> added, removed, unchanged;
};

inline SessionDelta compareSessions(const std::vector<Group>& left, const std::vector<Group>& right) {
    SessionDelta out;
    std::unordered_set<std::string> old, now;
    auto key = [](const Group& g, const Finding& f) {
        return std::to_string(g.name.size()) + ":" + g.name + f.value;
    };
    for (const auto& g : left) for (const auto& f : g.items) old.insert(key(g, f));
    for (const auto& g : right) for (const auto& f : g.items) now.insert(key(g, f));
    auto append = [](std::vector<Group>& groups, const Group& g, const Finding& f) {
        if (groups.empty() || groups.back().name != g.name) groups.push_back({g.name, {}});
        groups.back().items.push_back(f);
    };
    for (const auto& g : right) for (const auto& f : g.items)
        append(old.count(key(g, f)) ? out.unchanged : out.added, g, f);
    for (const auto& g : left) for (const auto& f : g.items)
        if (!now.count(key(g, f))) append(out.removed, g, f);
    return out;
}

inline std::string serializeJob(const ScanJob& j) {
    std::ostringstream s;
    const auto& o = j.options;
    const auto& f = j.files;
    s << "SRJOB2 " << std::quoted(j.name) << ' ' << j.pid << ' ' << j.monitorSeconds << ' '
      << int(o.mode) << ' ' << o.ascii << ' ' << o.utf16 << ' ' << o.base64 << ' ' << o.hex << ' '
      << o.minRun << ' ' << o.maxCandidate << ' ' << std::quoted(o.customRegex) << ' '
      << std::quoted(o.customLabel) << ' ' << o.customWholeWord << ' ' << o.caseInsensitive << ' '
      << o.dropCrap << ' ' << std::quoted(f.include) << ' ' << std::quoted(f.exclude) << ' '
      << f.minSize << ' ' << f.maxSize << ' ' << f.modifiedAfter << ' ' << f.modifiedBefore << ' '
      << f.rangeStart << ' ' << f.rangeEnd << ' ';
    auto strings = [&](const auto& list) {
        s << list.size() << ' ';
        for (const auto& item : list) s << std::quoted(item) << ' ';
    };
    strings(o.presets); strings(o.schemes);
    s << j.sources.size() << ' ';
    for (const auto& p : j.sources) {
        auto utf8 = p.u8string();
        s << std::quoted(std::string(utf8.begin(), utf8.end())) << ' ';
    }
    s << o.extraPatterns.size() << ' ';
    for (const auto& [label, pattern] : o.extraPatterns)
        s << std::quoted(label) << ' ' << std::quoted(pattern) << ' ';
    s << "ESC " << o.escaped << ' ';
    return s.str();
}

inline std::optional<ScanJob> parseJob(const std::string& data) {
    ScanJob j; std::istringstream s(data); std::string magic;
    int mode;
    auto& o = j.options; auto& f = j.files;
    if (!(s >> magic) || magic != "SRJOB2" ||
        !(s >> std::quoted(j.name) >> j.pid >> j.monitorSeconds >> mode >>
          o.ascii >> o.utf16 >> o.base64 >> o.hex >> o.minRun >> o.maxCandidate >>
          std::quoted(o.customRegex) >> std::quoted(o.customLabel) >> o.customWholeWord >>
          o.caseInsensitive >> o.dropCrap >> std::quoted(f.include) >> std::quoted(f.exclude) >>
          f.minSize >> f.maxSize >> f.modifiedAfter >> f.modifiedBefore >> f.rangeStart >> f.rangeEnd))
        return std::nullopt;
    if (mode < 0 || mode > 1) return std::nullopt;
    o.mode = static_cast<Mode>(mode);
    auto strings = [&](std::vector<std::string>& list) {
        std::size_t n; if (!(s >> n) || n > 1024) return false;
        for (std::size_t i = 0; i < n; ++i) {
            std::string v; if (!(s >> std::quoted(v))) return false;
            list.push_back(std::move(v));
        }
        return true;
    };
    if (!strings(o.presets) || !strings(o.schemes)) return std::nullopt;
    std::size_t n; if (!(s >> n) || n > 1024) return std::nullopt;
    for (std::size_t i = 0; i < n; ++i) {
        std::string p; if (!(s >> std::quoted(p))) return std::nullopt;
        j.sources.push_back(std::filesystem::u8path(p));
    }
    s >> std::ws;
    if (!s.eof()) {
        if (!(s >> n)) return std::nullopt;
        if (n > 1024) return std::nullopt;
        for (std::size_t i = 0; i < n; ++i) {
            std::string label, pattern;
            if (!(s >> std::quoted(label) >> std::quoted(pattern))) return std::nullopt;
            o.extraPatterns.emplace_back(std::move(label), std::move(pattern));
        }
        s >> std::ws;
        if (!s.eof()) {
            std::string tag;
            if (!(s >> tag >> o.escaped) || tag != "ESC") return std::nullopt;
            s >> std::ws;
            if (!s.eof()) return std::nullopt;
        }
    }
    return j;
}

} // namespace ur
