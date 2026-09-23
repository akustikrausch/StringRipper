/* portable regex user preset file */
#pragma once
#include "scan_core.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace ur {

struct UserPreset {
    std::string name;
    std::string description;
    std::string pattern;
    std::string positiveExamples, negativeExamples; // one test case per line
    bool validated = false;
    bool ascii = true, utf16 = true, hex = false, base64 = false;
    bool custom = true, email = false, ipv4 = false, ipv6 = false;
    bool guid = false, apiKey = false, filepath = false, download = false;
};

inline Options presetOptions(const UserPreset& p) {
    Options o; o.mode = Mode::Regex;
    o.ascii = p.ascii; o.utf16 = p.utf16; o.hex = p.hex; o.base64 = p.base64;
    if (p.custom) o.customRegex = p.pattern;
    o.customLabel = p.name;
    if (p.email) o.presets.push_back("email");
    if (p.ipv4) o.presets.push_back("ipv4");
    if (p.ipv6) o.presets.push_back("ipv6");
    if (p.guid) o.presets.push_back("guid");
    if (p.apiKey) o.presets.push_back("apikey");
    if (p.filepath) o.presets.push_back("filepath");
    if (p.download) o.presets.push_back("fileurl");
    if (p.custom && p.pattern.empty()) throw RegexError("Custom regex is empty");
    if (!p.ascii && !p.utf16 && !p.hex && !p.base64) throw RegexError("Select at least one decoder");
    return o;
}

inline Options profileOptions(const std::vector<UserPreset>& presets) {
    if (presets.empty()) throw RegexError("Profile has no presets");
    Options out; out.mode = Mode::Regex;
    out.ascii = out.utf16 = out.hex = out.base64 = false;
    for (const auto& p : presets) {
        auto item = presetOptions(p);
        out.ascii |= item.ascii; out.utf16 |= item.utf16;
        out.hex |= item.hex; out.base64 |= item.base64;
        for (const auto& builtin : item.presets)
            if (std::find(out.presets.begin(), out.presets.end(), builtin) == out.presets.end())
                out.presets.push_back(builtin);
        if (!item.customRegex.empty()) {
            if (out.customRegex.empty()) { out.customRegex = item.customRegex; out.customLabel = p.name; }
            else out.extraPatterns.emplace_back(p.name, item.customRegex);
        }
    }
    return out;
}

struct ExampleReport {
    std::size_t passed = 0, failed = 0;
    std::vector<std::string> failures;
};
inline ExampleReport testPresetExamples(const UserPreset& preset) {
    Detector detector(presetOptions(preset));
    ExampleReport report;
    auto check = [&](const std::string& text, bool expected) {
        std::istringstream lines(text); std::string line;
        while (std::getline(lines, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.empty()) continue;
            Sink sink; detector.testText(line, sink);
            if ((!sink.items.empty()) == expected) ++report.passed;
            else { ++report.failed; report.failures.push_back(
                std::string(expected ? "Expected match: " : "Unexpected match: ") + line); }
        }
    };
    check(preset.positiveExamples, true);
    check(preset.negativeExamples, false);
    return report;
}


inline std::string presetTrim(std::string s) {
    auto ws = [](unsigned char c) { return std::isspace(c) != 0; };
    s.erase(s.begin(), std::find_if_not(s.begin(), s.end(), ws));
    s.erase(std::find_if_not(s.rbegin(), s.rend(), ws).base(), s.end());
    return s;
}

inline bool presetBool(const std::string& s, bool fallback = false) {
    std::string v = presetTrim(s);
    std::transform(v.begin(), v.end(), v.begin(), [](unsigned char c) { return char(std::tolower(c)); });
    if (v == "1" || v == "true" || v == "yes" || v == "on") return true;
    if (v == "0" || v == "false" || v == "no" || v == "off") return false;
    return fallback;
}

inline std::string presetValue(const std::string& s) {
    std::string v;
    v.reserve(s.size());
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 1 < s.size() && s[i + 1] == 'n') { v.push_back('\n'); ++i; }
        else if (s[i] == '\\' && i + 1 < s.size() && s[i + 1] == 'r') { v.push_back('\r'); ++i; }
        else if (s[i] == '\\' && i + 1 < s.size() && s[i + 1] == '\\') { v.push_back('\\'); ++i; }
        else v.push_back(s[i]);
    }
    return v;
}

inline std::string presetEscape(const std::string& s) {
    std::string v;
    v.reserve(s.size());
    for (char c : s) {
        if (c == '\\') v += "\\\\";
        else if (c == '\r') v += "\\r";
        else if (c == '\n') v += "\\n";
        else v.push_back(c);
    }
    return v;
}

inline std::vector<UserPreset> parseUserPresets(const std::string& text, std::string* error = nullptr) {
    if (error) error->clear();
    std::vector<UserPreset> out;
    UserPreset* p = nullptr;
    std::istringstream in(text);
    std::string line;
    int no = 0;
    auto fail = [&](const std::string& why) {
        if (error) *error = "line " + std::to_string(no) + ": " + why;
        return std::vector<UserPreset>{};
    };
    std::vector<std::string> keys;
    while (std::getline(in, line)) {
        ++no;
        if (no == 1 && line.compare(0, 3, "\xEF\xBB\xBF") == 0) line.erase(0, 3);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        std::string t = presetTrim(line);
        if (t.empty() || t[0] == ';' || t[0] == '#') continue;
        if (t.front() == '[' && t.back() == ']') {
            if (p && std::find(keys.begin(), keys.end(), "Regex") == keys.end())
                return fail("missing Regex key");
            std::string h = presetTrim(t.substr(1, t.size() - 2));
            static const std::string prefix = "Regex User Preset:";
            if (h.compare(0, prefix.size(), prefix) != 0) return fail("unknown preset section");
            UserPreset n; n.name = presetTrim(h.substr(prefix.size()));
            for (const auto& old : out) {
                auto a = old.name, b = n.name;
                for (char& c : a) c = char(std::tolower(static_cast<unsigned char>(c)));
                for (char& c : b) c = char(std::tolower(static_cast<unsigned char>(c)));
                if (a == b) return fail("duplicate preset name");
            }
            if (n.name.empty()) {
                if (error) *error = "line " + std::to_string(no) + ": preset name is empty";
                return {};
            }
            out.push_back(std::move(n)); p = &out.back();
            keys.clear();
            continue;
        }
        if (!p) return fail("expected a preset section");
        auto eq = line.find('=');
        if (eq == std::string::npos) {
            if (error) *error = "line " + std::to_string(no) + ": expected key=value";
            return {};
        }
        std::string k = presetTrim(line.substr(0, eq)), v = presetValue(line.substr(eq + 1));
        if (std::find(keys.begin(), keys.end(), k) != keys.end()) return fail("duplicate key: " + k);
        keys.push_back(k);
        if (k != "Description" && k != "Regex" && k != "Positive" && k != "Negative" &&
            presetBool(v, true) != presetBool(v, false))
            return fail("expected a boolean for " + k);
        if (k == "Description") p->description = v;
        else if (k == "Regex") p->pattern = v;
        else if (k == "Positive") p->positiveExamples = v;
        else if (k == "Negative") p->negativeExamples = v;
        else if (k == "Validated") p->validated = presetBool(v);
        else if (k == "ASCII") p->ascii = presetBool(v);
        else if (k == "UTF-16") p->utf16 = presetBool(v);
        else if (k == "HEX") p->hex = presetBool(v);
        else if (k == "BASE64") p->base64 = presetBool(v);
        else if (k == "Custom") p->custom = presetBool(v);
        else if (k == "Email") p->email = presetBool(v);
        else if (k == "IPv4") p->ipv4 = presetBool(v);
        else if (k == "IPv6") p->ipv6 = presetBool(v);
        else if (k == "GUID") p->guid = presetBool(v);
        else if (k == "APIKey") p->apiKey = presetBool(v);
        else if (k == "Filepath") p->filepath = presetBool(v);
        else if (k == "Download") p->download = presetBool(v);
        else return fail("unknown key: " + k);
    }
    if (p && std::find(keys.begin(), keys.end(), "Regex") == keys.end()) return fail("missing Regex key");
    return out;
}

inline std::string serializeUserPresets(const std::vector<UserPreset>& presets) {
    std::string out = "; StringRipper regex user presets\n; Saved automatically. The previous file is kept as .bak.\n\n";
    for (const auto& p : presets) {
        out += "[Regex User Preset: " + p.name + "]\n";
        out += "Description=" + presetEscape(p.description) + "\n";
        out += "Regex=" + presetEscape(p.pattern) + "\n";
        out += "Positive=" + presetEscape(p.positiveExamples) + "\n";
        out += "Negative=" + presetEscape(p.negativeExamples) + "\n";
        out += "Validated=" + std::to_string(p.validated) + "\n\n";
        out += "ASCII=" + std::to_string(p.ascii) + "\nUTF-16=" + std::to_string(p.utf16);
        out += "\nHEX=" + std::to_string(p.hex) + "\nBASE64=" + std::to_string(p.base64) + "\n\n";
        out += "Custom=" + std::to_string(p.custom) + "\nEmail=" + std::to_string(p.email);
        out += "\nIPv4=" + std::to_string(p.ipv4) + "\nIPv6=" + std::to_string(p.ipv6);
        out += "\nGUID=" + std::to_string(p.guid) + "\nAPIKey=" + std::to_string(p.apiKey);
        out += "\nFilepath=" + std::to_string(p.filepath) + "\nDownload=" + std::to_string(p.download) + "\n\n";
    }
    return out;
}

inline bool loadUserPresets(const std::filesystem::path& path, std::vector<UserPreset>& presets,
                            std::string* error = nullptr) {
    if (error) error->clear();
    std::ifstream f(path, std::ios::binary);
    if (!f) { if (error) *error = "could not open preset file"; return false; }
    std::string text((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    if (text.empty()) { if (error) *error = "empty preset file"; return false; }
    if (f.bad()) { if (error) *error = "could not read preset file"; return false; }
    std::string issue;
    auto p = parseUserPresets(text, &issue);
    if (!issue.empty()) { if (error) *error = issue; return false; }
    presets = std::move(p);
    return true;
}

inline std::filesystem::path executablePresets(const std::filesystem::path& argv0) {
#ifdef _WIN32
    std::wstring path(32768, L'\0');
    auto n = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    if (n && n < path.size()) { path.resize(n); return std::filesystem::path(path).parent_path() / "regex-user-presets.ini"; }
#elif defined(__linux__)
    std::error_code ec;
    auto path = std::filesystem::read_symlink("/proc/self/exe", ec);
    if (!ec) return path.parent_path() / "regex-user-presets.ini";
#elif defined(__APPLE__)
    uint32_t n = 0;
    _NSGetExecutablePath(nullptr, &n);
    std::vector<char> path(n);
    if (_NSGetExecutablePath(path.data(), &n) == 0)
        return std::filesystem::weakly_canonical(path.data()).parent_path() / "regex-user-presets.ini";
#endif
    return std::filesystem::absolute(argv0).parent_path() / "regex-user-presets.ini";
}

struct PresetCli {
    Options options;
    std::vector<UserPreset> presets;
    bool list = false;
};

inline PresetCli presetCli(const std::vector<std::string>& args, std::filesystem::path file) {
    PresetCli result;
    std::vector<std::string> names;
    for (std::size_t i = 0; i < args.size(); ++i) {
        const auto& a = args[i];
        if (a == "--help" || a == "-h" || a == "/?") return {};
        if (a == "--list-user-presets") { result.list = true; continue; }
        if (a == "--user-preset" || a == "--presets-file" || a == "--regex" || a == "--preset" ||
            a == "--file" || a == "--folder" || a == "--pid" || a == "--scheme" ||
            a == "--out" || a == "--format") {
            if (++i == args.size()) throw std::invalid_argument("missing value for " + a);
            if (a == "--user-preset") { if (args[i].empty()) throw RegexError("preset name is empty"); names.push_back(args[i]); }
            if (a == "--presets-file") file = std::filesystem::u8path(args[i]);
        }
    }
    if (result.list || !names.empty()) {
        std::string error;
        if (!loadUserPresets(file, result.presets, &error)) throw std::runtime_error(error);
        if (!names.empty()) {
            std::vector<UserPreset> profile;
            for (const auto& name : names) {
                auto p = std::find_if(result.presets.begin(), result.presets.end(),
                                      [&](const UserPreset& p) { return p.name == name; });
                if (p == result.presets.end()) throw RegexError("unknown user preset: " + name);
                profile.push_back(*p);
            }
            result.options = profileOptions(profile);
        }
    }
    return result;
}

inline bool saveUserPresets(const std::filesystem::path& path, const std::vector<UserPreset>& presets,
                            std::string* error = nullptr) {
    if (error) error->clear();
    for (const auto& p : presets) {
        if (presetTrim(p.name).empty() || p.name.find_first_of("]\r\n") != std::string::npos) {
            if (error) *error = "invalid preset name";
            return false;
        }
    }
    std::string text = serializeUserPresets(presets), issue;
    parseUserPresets(text, &issue);
    if (!issue.empty()) { if (error) *error = issue; return false; }
    std::filesystem::path tmp = path; tmp += ".tmp";
    std::filesystem::path bak = path; bak += ".bak";
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        f.write(text.data(), static_cast<std::streamsize>(text.size()));
        f.flush();
        f.close();
        if (!f) {
            if (error) *error = "could not write temporary preset file";
            return false;
        }
    }
    std::error_code ec;
    std::vector<UserPreset> old;
    if (std::filesystem::exists(path, ec) && loadUserPresets(path, old)) {
        std::filesystem::copy_file(path, bak, std::filesystem::copy_options::overwrite_existing, ec);
        if (ec) { std::filesystem::remove(tmp, ec); if (error) *error = "could not create preset backup"; return false; }
    }
#ifdef _WIN32
    ec.clear();
    if (!MoveFileExW(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        ec = std::error_code(GetLastError(), std::system_category());
#else
    std::filesystem::rename(tmp, path, ec);
#endif
    if (ec) {
        std::filesystem::remove(tmp, ec);
        if (error) *error = "could not replace preset file; original file unchanged";
        return false;
    }
    return true;
}

} // namespace ur
