// scan_core.hpp - portable detection core for URLRipper.
//
// No platform headers here: this compiles on any C++20 compiler so the core
// can be unit-tested outside Windows. The Win32 process/file plumbing lives in
// win_process.hpp / file_read.hpp; the GUI in main.cpp.
//
// What it does: take a raw byte buffer (a chunk of process memory or a file),
// pull candidate strings out of it in several encodings (ASCII/ANSI/UTF-8,
// UTF-16 LE and BE, plus one level of Base64 and Hex decoding), and match them
// either as URLs (grouped by domain) or against a set of regex patterns
// (grouped by pattern). Results are de-duplicated and, at the end, grouped and
// sorted alphabetically descending (Z to A), as requested.

#pragma once

#include <algorithm>
#include <cstdint>
#include <regex>
#include <string>
#include <unordered_set>
#include <vector>

namespace ur {

enum class Enc { Ascii, Utf16, Base64, Hex };

inline const char* encName(Enc e) {
    switch (e) {
        case Enc::Ascii:  return "ASCII";
        case Enc::Utf16:  return "UTF-16";
        case Enc::Base64: return "Base64";
        case Enc::Hex:    return "Hex";
    }
    return "?";
}

enum class Mode { Urls, Regex };

struct Options {
    // Which decoders run. ASCII covers ASCII/ANSI/UTF-8 (URLs and most patterns
    // are ASCII bytes either way); UTF-16 covers wide strings; Base64 and Hex
    // decode embedded runs and re-scan the result one level deep.
    bool ascii  = true;
    bool utf16  = true;
    bool base64 = true;
    bool hex    = true;

    std::size_t minRun = 4;      // shortest printable run kept as a candidate
    std::size_t maxCandidate = 8192; // skip absurdly long runs (bounds regex cost)

    Mode mode = Mode::Urls;

    // URL mode: allowed schemes, lower-case, no "://". Empty = all known schemes.
    std::vector<std::string> schemes;

    // Regex mode: preset ids (see builtinPresets) and an optional custom pattern.
    std::vector<std::string> presets;
    std::string customRegex;     // ECMAScript syntax; empty = none
    bool customWholeWord = false;
    bool caseInsensitive = false;
};

struct Finding {
    std::string value;
    Enc         enc;
    std::string source;   // e.g. "spotify.exe+0x1a2f" or "C:\path\file.bin"
    std::string group;    // domain (URL mode) or pattern name (regex mode)
};

struct Group {
    std::string name;
    std::vector<Finding> items;
};

struct Preset {
    std::string id;       // stable id, e.g. "email"
    std::string label;    // shown in the UI
    std::string pattern;  // ECMAScript regex
};

// Curated, safe presets (no catastrophic backtracking). Windows-oriented paths.
inline const std::vector<Preset>& builtinPresets() {
    static const std::vector<Preset> p = {
        {"email",    "Email address", R"([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})"},
        {"ipv4",     "IPv4 address",  R"(\b(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\b)"},
        {"ipv6",     "IPv6 address",  R"(\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b)"},
        {"guid",     "GUID",          R"(\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b)"},
        {"apikey",   "API key",       R"(\b(?:AKIA[0-9A-Z]{16}|gh[opusr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9\-]{10,}|sk_(?:live|test)_[A-Za-z0-9]{16,})\b)"},
        {"filepath", "File path",     R"((?:[A-Za-z]:\\|\\\\)[^\r\n"<>|?*\x00]{2,})"},
    };
    return p;
}

class RegexError : public std::runtime_error {
public:
    explicit RegexError(const std::string& what) : std::runtime_error(what) {}
};

namespace detail {

inline bool isPrintable(uint8_t b) { return b >= 0x20 && b <= 0x7E; }

inline bool isBase64Char(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '-' || c == '_';
}

inline bool isHexChar(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

inline int b64val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+' || c == '-') return 62;
    if (c == '/' || c == '_') return 63;
    return -1;
}

inline std::string decodeBase64(const std::string& s) {
    std::string out;
    int val = 0, bits = 0;
    for (char c : s) {
        int d = b64val(c);
        if (d < 0) break;
        val = (val << 6) | d;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<char>((val >> bits) & 0xFF));
        }
    }
    return out;
}

inline std::string decodeHex(const std::string& s) {
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return 0;
    };
    std::string out;
    out.reserve(s.size() / 2);
    for (std::size_t i = 0; i + 1 < s.size(); i += 2)
        out.push_back(static_cast<char>((nib(s[i]) << 4) | nib(s[i + 1])));
    return out;
}

// Printable ASCII/ANSI/UTF-8 runs.
inline void extractAscii(const uint8_t* d, std::size_t n, std::size_t minRun,
                         std::vector<std::string>& out) {
    std::string cur;
    for (std::size_t i = 0; i < n; ++i) {
        if (isPrintable(d[i])) {
            cur.push_back(static_cast<char>(d[i]));
        } else {
            if (cur.size() >= minRun) out.push_back(cur);
            cur.clear();
        }
    }
    if (cur.size() >= minRun) out.push_back(cur);
}

// UTF-16 runs. le=true -> [char,0x00]; le=false -> [0x00,char].
inline void extractUtf16(const uint8_t* d, std::size_t n, bool le, std::size_t minRun,
                         std::vector<std::string>& out) {
    std::string cur;
    for (std::size_t i = 0; i + 1 < n; i += 2) {
        uint8_t lo = le ? d[i] : d[i + 1];
        uint8_t hi = le ? d[i + 1] : d[i];
        if (hi == 0x00 && isPrintable(lo)) {
            cur.push_back(static_cast<char>(lo));
        } else {
            if (cur.size() >= minRun) out.push_back(cur);
            cur.clear();
        }
    }
    if (cur.size() >= minRun) out.push_back(cur);
}

// Maximal runs of a character class, decoded, returned as byte strings.
template <typename Pred, typename Dec>
inline void decodeRuns(const std::string& s, std::size_t minRun, bool needEven,
                       Pred isMember, Dec decode, std::vector<std::string>& out) {
    std::size_t i = 0;
    while (i < s.size()) {
        if (!isMember(s[i])) { ++i; continue; }
        std::size_t j = i;
        while (j < s.size() && isMember(s[j])) ++j;
        std::size_t len = j - i;
        if (len >= minRun) {
            std::string run = s.substr(i, len);
            if (needEven && (run.size() % 2)) run.pop_back();
            std::string dec = decode(run);
            // Keep only if the decode produced something with printable content.
            std::size_t printable = 0;
            for (unsigned char c : dec) if (isPrintable(c)) ++printable;
            if (dec.size() >= 4 && printable * 2 >= dec.size())
                out.push_back(std::move(dec));
        }
        i = j;
    }
}

inline std::string trimUrl(std::string u) {
    static const std::string trailing = ".,;:!?)]}'\"><";
    while (!u.empty() && trailing.find(u.back()) != std::string::npos) u.pop_back();
    return u;
}

inline std::string urlScheme(const std::string& u) {
    auto p = u.find("://");
    if (p == std::string::npos) return {};
    std::string s = u.substr(0, p);
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
    return s;
}

inline std::string urlHost(const std::string& u) {
    auto p = u.find("://");
    if (p == std::string::npos) return {};
    std::string rest = u.substr(p + 3);
    std::size_t end = rest.find_first_of("/?#");
    std::string authority = (end == std::string::npos) ? rest : rest.substr(0, end);
    auto at = authority.rfind('@');
    if (at != std::string::npos) authority = authority.substr(at + 1);
    auto colon = authority.find(':');
    if (colon != std::string::npos) authority = authority.substr(0, colon);
    std::transform(authority.begin(), authority.end(), authority.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return authority.empty() ? "(no host)" : authority;
}

} // namespace detail

class Scanner {
public:
    explicit Scanner(Options opt) : opt_(std::move(opt)) {
        urlMode_ = (opt_.mode == Mode::Urls);
        auto flags = std::regex::ECMAScript | std::regex::optimize;
        if (opt_.caseInsensitive) flags |= std::regex::icase;
        if (urlMode_) {
            urlRe_ = std::regex(
                R"((?:https?|ftps?|wss?|rtsp|rtmp|mms|udp)://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%\-]+)",
                std::regex::ECMAScript | std::regex::icase | std::regex::optimize);
        } else {
            for (const auto& id : opt_.presets) {
                for (const auto& p : builtinPresets()) {
                    if (p.id == id) {
                        try { matchers_.emplace_back(p.pattern, flags); }
                        catch (const std::regex_error& e) { throw RegexError(std::string("preset ") + id + ": " + e.what()); }
                        names_.push_back(p.label);
                    }
                }
            }
            if (!opt_.customRegex.empty()) {
                std::string pat = opt_.customRegex;
                if (opt_.customWholeWord) pat = "\\b(?:" + pat + ")\\b";
                try { matchers_.emplace_back(pat, flags); }
                catch (const std::regex_error& e) { throw RegexError(std::string("custom regex: ") + e.what()); }
                names_.push_back("Custom");
            }
            if (matchers_.empty()) throw RegexError("no pattern selected");
        }
    }

    // Scan one buffer. `source` is a human label recorded on every finding.
    void feed(const uint8_t* data, std::size_t n, const std::string& source) {
        scanBuffer(data, n, source, 0);
    }

    // Group + sort (Z to A) the de-duplicated findings collected so far.
    std::vector<Group> finalize() {
        std::vector<Group> groups;
        for (auto& f : findings_) {
            auto it = std::find_if(groups.begin(), groups.end(),
                                   [&](const Group& g) { return g.name == f.group; });
            if (it == groups.end()) { groups.push_back({f.group, {f}}); }
            else it->items.push_back(f);
        }
        auto desc = [](const std::string& a, const std::string& b) {
            return std::lexicographical_compare(b.begin(), b.end(), a.begin(), a.end());
        };
        std::sort(groups.begin(), groups.end(),
                  [&](const Group& a, const Group& b) { return desc(a.name, b.name); });
        for (auto& g : groups)
            std::sort(g.items.begin(), g.items.end(),
                      [&](const Finding& a, const Finding& b) { return desc(a.value, b.value); });
        return groups;
    }

    std::size_t count() const { return findings_.size(); }

private:
    void matchString(const std::string& s, Enc enc, const std::string& source) {
        if (s.size() > opt_.maxCandidate) return;
        if (urlMode_) {
            auto begin = std::sregex_iterator(s.begin(), s.end(), urlRe_);
            auto end = std::sregex_iterator();
            for (auto it = begin; it != end; ++it) {
                std::string url = detail::trimUrl(it->str());
                if (url.size() < 8) continue;
                if (!opt_.schemes.empty()) {
                    std::string sc = detail::urlScheme(url);
                    if (std::find(opt_.schemes.begin(), opt_.schemes.end(), sc) == opt_.schemes.end())
                        continue;
                }
                add(url, enc, source, detail::urlHost(url));
            }
        } else {
            for (std::size_t i = 0; i < matchers_.size(); ++i) {
                auto begin = std::sregex_iterator(s.begin(), s.end(), matchers_[i]);
                auto end = std::sregex_iterator();
                for (auto it = begin; it != end; ++it) {
                    std::string v = it->str();
                    if (v.empty()) continue;
                    add(v, enc, source, names_[i]);
                }
            }
        }
    }

    void add(const std::string& value, Enc enc, const std::string& source, const std::string& group) {
        std::string key = group;
        key.push_back('\x01');
        key += value;
        if (!seen_.insert(key).second) return;   // de-dup within group
        findings_.push_back({value, enc, source, group});
    }

    void scanBuffer(const uint8_t* data, std::size_t n, const std::string& source, int depth) {
        std::vector<std::string> asciiRuns;
        if (opt_.ascii || depth > 0)
            detail::extractAscii(data, n, opt_.minRun, asciiRuns);
        for (const auto& s : asciiRuns) matchString(s, Enc::Ascii, source);

        std::vector<std::string> wideRuns;
        if (opt_.utf16) {
            detail::extractUtf16(data, n, true, opt_.minRun, wideRuns);
            detail::extractUtf16(data, n, false, opt_.minRun, wideRuns);
            for (const auto& s : wideRuns) matchString(s, Enc::Utf16, source);
        }

        if (depth == 0 && (opt_.base64 || opt_.hex)) {
            // Look for encoded runs inside the printable candidates we found.
            std::vector<const std::string*> pool;
            for (const auto& s : asciiRuns) pool.push_back(&s);
            for (const auto& s : wideRuns) pool.push_back(&s);
            for (const std::string* sp : pool) {
                if (opt_.base64) {
                    std::vector<std::string> dec;
                    detail::decodeRuns(*sp, 16, false, detail::isBase64Char, detail::decodeBase64, dec);
                    for (auto& d : dec)
                        scanDecoded(reinterpret_cast<const uint8_t*>(d.data()), d.size(), source, Enc::Base64);
                }
                if (opt_.hex) {
                    std::vector<std::string> dec;
                    detail::decodeRuns(*sp, 16, true, detail::isHexChar, detail::decodeHex, dec);
                    for (auto& d : dec)
                        scanDecoded(reinterpret_cast<const uint8_t*>(d.data()), d.size(), source, Enc::Hex);
                }
            }
        }
    }

    // Re-scan decoded bytes (one level), labelling every finding with the
    // encoding it was hidden behind rather than the inner ASCII/UTF-16 pass.
    void scanDecoded(const uint8_t* data, std::size_t n, const std::string& source, Enc enc) {
        std::vector<std::string> runs;
        detail::extractAscii(data, n, opt_.minRun, runs);
        detail::extractUtf16(data, n, true, opt_.minRun, runs);
        for (const auto& s : runs) matchString(s, enc, source);
    }

    Options opt_;
    bool urlMode_ = true;
    std::regex urlRe_;
    std::vector<std::regex> matchers_;
    std::vector<std::string> names_;
    std::unordered_set<std::string> seen_;
    std::vector<Finding> findings_;
};

} // namespace ur
