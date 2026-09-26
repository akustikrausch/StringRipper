#pragma once

#include "scan_core.hpp"
#include <cctype>
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
    if (!s.empty() && (s[0] == '=' || s[0] == '+' || s[0] == '-' || s[0] == '@' || s[0] == '\t'))
        out += '\'';
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
    for (bool b : {o.ascii, o.utf16, o.base64, o.hex, o.escaped, o.customWholeWord, o.caseInsensitive, o.dropCrap})
        add(b ? "1" : "0");
    add(std::to_string(o.minRun)); add(std::to_string(o.maxCandidate));
    add(std::to_string(o.presets.size()));
    for (const auto& s : o.presets) add(s);
    add(std::to_string(o.schemes.size()));
    for (const auto& s : o.schemes) add(s);
    return key;
}

/* ignore list, one rule per line, case-insensitive:
     microsoft.com   that group and every group ending in .microsoft.com
                     (URL hosts; a regex pattern label matches by name)
     *telemetry*     values matching the glob, * and ?
     =value          exactly this value
   blank lines and lines starting with # are skipped */
struct IgnoreRules {
    std::vector<std::string> groups, globs, exact;

    static std::string low(std::string s) {
        for (char& c : s) c = char(std::tolower(static_cast<unsigned char>(c)));
        return s;
    }
    static IgnoreRules parse(const std::vector<std::string>& lines) {
        IgnoreRules r;
        for (const auto& line : lines) {
            std::size_t a = line.find_first_not_of(" \t\r\n"), b = line.find_last_not_of(" \t\r\n");
            if (a == std::string::npos || line[a] == '#') continue;
            std::string rule = low(line.substr(a, b - a + 1));
            if (rule[0] == '=') { if (rule.size() > 1) r.exact.push_back(rule.substr(1)); }
            else if (rule.find_first_of("*?") != std::string::npos) r.globs.push_back(rule);
            else r.groups.push_back(rule);
        }
        return r;
    }
    bool empty() const { return groups.empty() && globs.empty() && exact.empty(); }
    static bool glob(const std::string& p, const std::string& s) {
        std::size_t i = 0, j = 0, star = std::string::npos, mark = 0;
        while (j < s.size()) {
            if (i < p.size() && (p[i] == '?' || p[i] == s[j])) { ++i; ++j; }
            else if (i < p.size() && p[i] == '*') { star = i++; mark = j; }
            else if (star != std::string::npos) { i = star + 1; j = ++mark; }
            else return false;
        }
        while (i < p.size() && p[i] == '*') ++i;
        return i == p.size();
    }
    bool hidesGroup(const std::string& name) const {
        if (groups.empty()) return false;
        const std::string g = low(name);
        for (const auto& h : groups)
            if (g == h || (g.size() > h.size() && g[g.size() - h.size() - 1] == '.' &&
                           g.compare(g.size() - h.size(), h.size(), h) == 0)) return true;
        return false;
    }
    bool hidesValue(const std::string& value) const {
        if (globs.empty() && exact.empty()) return false;
        const std::string v = low(value);
        for (const auto& e : exact) if (v == e) return true;
        for (const auto& p : globs) if (glob(p, v)) return true;
        return false;
    }
};

inline std::vector<Group> filterIgnored(const std::vector<Group>& groups, const IgnoreRules& rules,
                                        std::size_t* hidden = nullptr) {
    std::vector<Group> out;
    std::size_t gone = 0;
    for (const auto& g : groups) {
        if (rules.hidesGroup(g.name)) { gone += g.items.size(); continue; }
        Group keep{g.name, {}};
        for (const auto& f : g.items)
            if (rules.hidesValue(f.value)) ++gone; else keep.items.push_back(f);
        if (!keep.items.empty()) out.push_back(std::move(keep));
    }
    if (hidden) *hidden = gone;
    return out;
}

} // namespace ur
