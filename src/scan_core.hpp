// scan_core.hpp - portable, thread-safe detection core for URLRipper.
//
// No platform headers: compiles anywhere, so the core has a self-test outside
// Windows. It takes a raw byte buffer (a window of process memory or a file
// chunk), pulls candidate strings out of it across encodings (ASCII/ANSI/UTF-8,
// UTF-16 LE/BE, plus one level of Base64 and Hex), and matches them as URLs
// (fast hand-rolled scan, no std::regex) or against regex patterns. Each thread
// scans into its OWN Sink; mergeSinks() de-duplicates globally, groups and sorts
// Z to A. The Detector is immutable and shared across threads.

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
    bool ascii  = true;    // ASCII/ANSI/UTF-8 printable runs
    bool utf16  = true;    // UTF-16 LE and BE
    bool base64 = true;    // decode embedded Base64 one level
    bool hex    = true;    // decode embedded Hex one level

    std::size_t minRun = 4;
    std::size_t maxCandidate = 8192;   // skip absurd runs (bounds regex cost)

    Mode mode = Mode::Urls;

    std::vector<std::string> schemes;   // URL mode: allowed schemes (empty = all)

    std::vector<std::string> presets;   // regex mode preset ids
    std::string customRegex;
    bool customWholeWord = false;
    bool caseInsensitive = false;
};

struct Finding {
    std::string value;
    Enc         enc;
    std::string source;
    std::string group;
};

struct Group {
    std::string name;
    std::vector<Finding> items;
};

struct Preset {
    std::string id;
    std::string label;
    std::string pattern;
};

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

// Per-thread accumulator. Each worker owns one; scanning never shares state.
struct Sink {
    std::vector<Finding> items;
    std::unordered_set<std::string> seen;   // "group\x01value"
    void add(const std::string& value, Enc enc, const std::string& source, const std::string& group) {
        std::string key = group;
        key.push_back('\x01');
        key += value;
        if (!seen.insert(key).second) return;
        items.push_back({value, enc, source, group});
    }
};

namespace detail {

inline bool isPrintable(uint8_t b) { return b >= 0x20 && b <= 0x7E; }
inline bool isAlpha(char c) { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'); }
inline bool isBase64Char(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '-' || c == '_';
}
inline bool isHexChar(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}
// URL body characters (after "scheme://").
inline bool isUrlChar(char c) {
    if (isAlpha(c) || (c >= '0' && c <= '9')) return true;
    switch (c) {
        case '.': case '_': case '~': case ':': case '/': case '?': case '#':
        case '[': case ']': case '@': case '!': case '$': case '&': case '\'':
        case '(': case ')': case '*': case '+': case ',': case ';': case '=':
        case '%': case '-':
            return true;
        default: return false;
    }
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
        val = (val << 6) | d; bits += 6;
        if (bits >= 8) { bits -= 8; out.push_back(char((val >> bits) & 0xFF)); }
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
        out.push_back(char((nib(s[i]) << 4) | nib(s[i + 1])));
    return out;
}

inline void extractAscii(const uint8_t* d, std::size_t n, std::size_t minRun,
                         std::vector<std::string>& out) {
    std::string cur;
    for (std::size_t i = 0; i < n; ++i) {
        if (isPrintable(d[i])) cur.push_back(char(d[i]));
        else { if (cur.size() >= minRun) out.push_back(cur); cur.clear(); }
    }
    if (cur.size() >= minRun) out.push_back(cur);
}
inline void extractUtf16(const uint8_t* d, std::size_t n, bool le, std::size_t minRun,
                         std::vector<std::string>& out) {
    std::string cur;
    for (std::size_t i = 0; i + 1 < n; i += 2) {
        uint8_t lo = le ? d[i] : d[i + 1];
        uint8_t hi = le ? d[i + 1] : d[i];
        if (hi == 0x00 && isPrintable(lo)) cur.push_back(char(lo));
        else { if (cur.size() >= minRun) out.push_back(cur); cur.clear(); }
    }
    if (cur.size() >= minRun) out.push_back(cur);
}

template <typename Pred, typename Dec>
inline void decodeRuns(const std::string& s, std::size_t minRun, bool needEven,
                       Pred isMember, Dec decode, std::vector<std::string>& out) {
    std::size_t i = 0;
    while (i < s.size()) {
        if (!isMember(s[i])) { ++i; continue; }
        std::size_t j = i;
        while (j < s.size() && isMember(s[j])) ++j;
        if (j - i >= minRun) {
            std::string run = s.substr(i, j - i);
            if (needEven && (run.size() % 2)) run.pop_back();
            std::string dec = decode(run);
            std::size_t printable = 0;
            for (unsigned char c : dec) if (isPrintable(c)) ++printable;
            if (dec.size() >= 4 && printable * 2 >= dec.size()) out.push_back(std::move(dec));
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
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return char(std::tolower(c)); });
    return s;
}
inline std::string urlHost(const std::string& u) {
    auto p = u.find("://");
    if (p == std::string::npos) return {};
    std::string rest = u.substr(p + 3);
    std::size_t end = rest.find_first_of("/?#");
    std::string a = (end == std::string::npos) ? rest : rest.substr(0, end);
    auto at = a.rfind('@');
    if (at != std::string::npos) a = a.substr(at + 1);
    auto colon = a.find(':');
    if (colon != std::string::npos) a = a.substr(0, colon);
    std::transform(a.begin(), a.end(), a.begin(), [](unsigned char c) { return char(std::tolower(c)); });
    return a.empty() ? "(no host)" : a;
}

inline bool schemeKnown(const std::string& s) {
    static const char* k[] = {"http", "https", "ftp", "ftps", "ws", "wss",
                              "rtsp", "rtmp", "mms", "udp"};
    for (const char* x : k) if (s == x) return true;
    return false;
}

} // namespace detail

class Detector {
public:
    explicit Detector(Options opt) : opt_(std::move(opt)) {
        urlMode_ = (opt_.mode == Mode::Urls);
        if (!urlMode_) {
            auto flags = std::regex::ECMAScript | std::regex::optimize;
            if (opt_.caseInsensitive) flags |= std::regex::icase;
            for (const auto& id : opt_.presets)
                for (const auto& p : builtinPresets())
                    if (p.id == id) {
                        try { matchers_.emplace_back(p.pattern, flags); }
                        catch (const std::regex_error& e) { throw RegexError("preset " + id + ": " + e.what()); }
                        names_.push_back(p.label);
                    }
            if (!opt_.customRegex.empty()) {
                std::string pat = opt_.customWholeWord ? ("\\b(?:" + opt_.customRegex + ")\\b") : opt_.customRegex;
                try { matchers_.emplace_back(pat, flags); }
                catch (const std::regex_error& e) { throw RegexError(std::string("custom regex: ") + e.what()); }
                names_.push_back("Custom");
            }
            if (matchers_.empty()) throw RegexError("no pattern selected");
        }
    }

    bool urlMode() const { return urlMode_; }

    // Thread-safe: writes only into the caller-owned sink.
    void scan(const uint8_t* data, std::size_t n, const std::string& source, Sink& sink) const {
        std::vector<std::string> ascii;
        detail::extractAscii(data, n, opt_.minRun, ascii);
        for (const auto& s : ascii) match(s, Enc::Ascii, source, sink);

        std::vector<std::string> wide;
        if (opt_.utf16) {
            detail::extractUtf16(data, n, true, opt_.minRun, wide);
            detail::extractUtf16(data, n, false, opt_.minRun, wide);
            for (const auto& s : wide) match(s, Enc::Utf16, source, sink);
        }

        if (opt_.base64 || opt_.hex) {
            auto decodeAndScan = [&](const std::string& sp) {
                if (opt_.base64) {
                    std::vector<std::string> dec;
                    detail::decodeRuns(sp, 16, false, detail::isBase64Char, detail::decodeBase64, dec);
                    for (auto& d : dec) scanDecoded(d, Enc::Base64, source, sink);
                }
                if (opt_.hex) {
                    std::vector<std::string> dec;
                    detail::decodeRuns(sp, 16, true, detail::isHexChar, detail::decodeHex, dec);
                    for (auto& d : dec) scanDecoded(d, Enc::Hex, source, sink);
                }
            };
            for (const auto& s : ascii) decodeAndScan(s);
            for (const auto& s : wide) decodeAndScan(s);
        }
    }

private:
    void scanDecoded(const std::string& d, Enc enc, const std::string& source, Sink& sink) const {
        std::vector<std::string> runs;
        detail::extractAscii(reinterpret_cast<const uint8_t*>(d.data()), d.size(), opt_.minRun, runs);
        detail::extractUtf16(reinterpret_cast<const uint8_t*>(d.data()), d.size(), true, opt_.minRun, runs);
        for (const auto& s : runs) match(s, enc, source, sink);
    }

    void match(const std::string& s, Enc enc, const std::string& source, Sink& sink) const {
        if (s.size() > opt_.maxCandidate) return;
        if (urlMode_) matchUrls(s, enc, source, sink);
        else matchRegex(s, enc, source, sink);
    }

    // Fast hand-rolled URL scan: find "://", grab the scheme left of it and the
    // body right of it, no std::regex.
    void matchUrls(const std::string& s, Enc enc, const std::string& source, Sink& sink) const {
        std::size_t pos = 0;
        while ((pos = s.find("://", pos)) != std::string::npos) {
            std::size_t start = pos;
            while (start > 0 && detail::isAlpha(s[start - 1])) --start;
            std::string scheme = s.substr(start, pos - start);
            std::transform(scheme.begin(), scheme.end(), scheme.begin(),
                           [](unsigned char c) { return char(std::tolower(c)); });
            if (scheme.empty() || !detail::schemeKnown(scheme)) { pos += 3; continue; }
            std::size_t end = pos + 3;
            while (end < s.size() && detail::isUrlChar(s[end])) ++end;
            std::string url = detail::trimUrl(s.substr(start, end - start));
            if (url.size() >= 8) {
                if (opt_.schemes.empty() ||
                    std::find(opt_.schemes.begin(), opt_.schemes.end(), scheme) != opt_.schemes.end())
                    sink.add(url, enc, source, detail::urlHost(url));
            }
            pos = end;
        }
    }

    void matchRegex(const std::string& s, Enc enc, const std::string& source, Sink& sink) const {
        for (std::size_t i = 0; i < matchers_.size(); ++i) {
            auto begin = std::sregex_iterator(s.begin(), s.end(), matchers_[i]);
            auto end = std::sregex_iterator();
            for (auto it = begin; it != end; ++it) {
                std::string v = it->str();
                if (!v.empty()) sink.add(v, enc, source, names_[i]);
            }
        }
    }

    Options opt_;
    bool urlMode_ = true;
    std::vector<std::regex> matchers_;
    std::vector<std::string> names_;
};

// Merge per-thread sinks: global de-dup, group (by domain/pattern), sort Z to A.
inline std::vector<Group> mergeSinks(std::vector<Sink>& sinks) {
    std::unordered_set<std::string> seen;
    std::vector<Group> groups;
    for (auto& sk : sinks) {
        for (auto& f : sk.items) {
            std::string key = f.group;
            key.push_back('\x01');
            key += f.value;
            if (!seen.insert(key).second) continue;
            auto it = std::find_if(groups.begin(), groups.end(),
                                   [&](const Group& g) { return g.name == f.group; });
            if (it == groups.end()) groups.push_back({f.group, {f}});
            else it->items.push_back(f);
        }
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

inline std::size_t countFindings(const std::vector<Group>& groups) {
    std::size_t n = 0;
    for (const auto& g : groups) n += g.items.size();
    return n;
}

} // namespace ur
