#pragma once

#include "scan_core.hpp"
#include <cstdio>
#include <unordered_map>
#include <map>
#include <sstream>

namespace ur {

inline std::string jsonString(const std::string& s) {
    std::string out = "\"";
    const char* hex = "0123456789abcdef";
    for (unsigned char c : s) {
        if (c == '"' || c == '\\') { out += '\\'; out += char(c); }
        else if (c < 0x20) { out += "\\u00"; out += hex[c >> 4]; out += hex[c & 15]; }
        else out += char(c);
    }
    return out + '"';
}

inline std::string csvField(const std::string& s) {
    std::string out = "\"";
    for (char c : s) { if (c == '"') out += '"'; out += c; }
    return out + '"';
}

inline std::string exportResults(const std::vector<Group>& groups, const std::string& format) {
    if (format != "txt" && format != "csv" && format != "json")
        throw std::invalid_argument("format must be txt, csv or json");
    std::string out = format == "csv" ?
        "group,value,encoding,source,offset,context_before,context_after,captures\r\n" :
        format == "json" ? "[\n" : "";
    bool first = true;
    for (const auto& g : groups) {
        if (format == "txt") {
            if (!out.empty()) out += "\r\n";
            out += g.name + "  (" + std::to_string(g.items.size()) + ")\r\n\r\n";
        }
        for (const auto& f : g.items) {
            if (format == "txt") {
                out += f.value;
                if (f.hasOffset) out += "  @0x" + [&] {
                    char b[32]; std::snprintf(b, sizeof(b), "%llX", (unsigned long long)f.offset);
                    return std::string(b);
                }();
                out += "\r\n";
            } else if (format == "csv") {
                std::string captures;
                for (const auto& [name, value] : f.captures) {
                    if (!captures.empty()) captures += "; ";
                    captures += name + "=" + value;
                }
                out += csvField(g.name) + "," + csvField(f.value) + "," +
                    csvField(encName(f.enc)) + "," + csvField(f.source) + "," +
                    csvField(f.hasOffset ? std::to_string(f.offset) : "") + "," +
                    csvField(f.before) + "," + csvField(f.after) + "," + csvField(captures) + "\r\n";
            } else {
                if (!first) out += ",\n";
                out += "  {\"group\":" + jsonString(g.name) + ",\"value\":" + jsonString(f.value) +
                    ",\"encoding\":" + jsonString(encName(f.enc)) + ",\"source\":" + jsonString(f.source) +
                    ",\"offset\":" + (f.hasOffset ? std::to_string(f.offset) : "null") +
                    ",\"contextBefore\":" + jsonString(f.before) + ",\"contextAfter\":" + jsonString(f.after) +
                    ",\"captures\":{";
                bool firstCapture = true;
                for (const auto& [name, value] : f.captures) {
                    if (!firstCapture) out += ",";
                    out += jsonString(name) + ":" + jsonString(value);
                    firstCapture = false;
                }
                out += "}}";
                first = false;
            }
        }
    }
    if (format == "json") out += "\n]\n";
    return out;
}

struct DashboardStats {
    std::size_t findings = 0;
    std::map<std::string, std::size_t> byGroup, bySource, byEncoding;
};
inline DashboardStats summarizeResults(const std::vector<Group>& groups) {
    DashboardStats stats;
    for (const auto& g : groups) for (const auto& f : g.items) {
        ++stats.findings;
        ++stats.byGroup[g.name];
        ++stats.bySource[f.source];
        ++stats.byEncoding[encName(f.enc)];
    }
    return stats;
}
inline std::string dashboardText(const DashboardStats& stats) {
    std::ostringstream out;
    out << stats.findings << " findings\r\n\r\n";
    auto section = [&](const char* title, const auto& values) {
        out << title << "\r\n";
        std::vector<std::pair<std::string, std::size_t>> sorted(values.begin(), values.end());
        std::sort(sorted.begin(), sorted.end(), [](const auto& a, const auto& b) {
            return a.second != b.second ? a.second > b.second : a.first < b.first;
        });
        for (const auto& [name, count] : sorted) out << count << "  " << name << "\r\n";
        out << "\r\n";
    };
    section("By pattern / group", stats.byGroup);
    section("By source", stats.bySource);
    section("By encoding", stats.byEncoding);
    return out.str();
}

class ScanComparison {
public:
    void clear() { baseline_.clear(); context_.clear(); ready_ = false; }
    bool matches(const std::string& context) const { return ready_ && context_ == context; }
    void remember(const std::string& context, const std::vector<Group>& groups) {
        baseline_ = index(groups); context_ = context; ready_ = true;
    }
    std::vector<Group> added(const std::vector<Group>& groups) const {
        std::vector<Group> out;
        for (const auto& g : groups) {
            Group fresh; fresh.name = g.name;
            const auto old = baseline_.find(g.name);
            for (const auto& f : g.items)
                if (old == baseline_.end() || !old->second.count(f.value)) fresh.items.push_back(f);
            if (!fresh.items.empty()) out.push_back(std::move(fresh));
        }
        return out;
    }
private:
    using Index = std::unordered_map<std::string, std::unordered_set<std::string>>;
    static Index index(const std::vector<Group>& groups) {
        Index out;
        for (const auto& g : groups) for (const auto& f : g.items) out[g.name].insert(f.value);
        return out;
    }
    Index baseline_;
    std::string context_;
    bool ready_ = false;
};

inline std::string comparisonContext(const std::string& source, const Options& o) {
    std::string key;
    auto add = [&](const std::string& s) { key += std::to_string(s.size()) + ":" + s; };
    add(source); add(o.customRegex); add(o.customLabel);
    for (const auto& [label, pattern] : o.extraPatterns) { add(label); add(pattern); }
    add(std::to_string(static_cast<int>(o.mode)));
    for (bool b : {o.ascii, o.utf16, o.base64, o.hex, o.customWholeWord, o.caseInsensitive, o.dropCrap})
        add(b ? "1" : "0");
    add(std::to_string(o.minRun)); add(std::to_string(o.maxCandidate));
    add(std::to_string(o.presets.size()));
    for (const auto& s : o.presets) add(s);
    add(std::to_string(o.schemes.size()));
    for (const auto& s : o.schemes) add(s);
    return key;
}

} // namespace ur
