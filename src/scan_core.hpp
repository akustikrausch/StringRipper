/* scan core: strings out of a byte window, matched as URLs or regex, Z->A.
   platform-free, one Sink per thread, merged at the end. */
#pragma once

#include <algorithm>
#include <cstdint>
#include <stdexcept>
#include <regex>
#include <string>
#include <unordered_map>
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
    bool ascii  = true;
    bool utf16  = true;
    bool base64 = true;
    bool hex    = true;
    std::size_t minRun = 4;
    std::size_t maxCandidate = 8192;
    Mode mode = Mode::Urls;
    std::vector<std::string> schemes;   /* URL mode, empty = all */
    std::vector<std::string> presets;
    std::string customRegex;
    std::string customLabel = "Custom";
    std::vector<std::pair<std::string, std::string>> extraPatterns; // label, ECMAScript regex
    bool customWholeWord = false;
    bool caseInsensitive = false;
    bool dropCrap = true;               /* URL mode: drop placeholder/namespace noise */
};

struct Finding {
    std::string value;
    Enc         enc;
    std::string source;
    std::string group;
    uint64_t offset = 0;
    bool hasOffset = false;
    std::string before, after;
    std::vector<std::pair<std::string, std::string>> captures;
};

inline std::string findingKey(const std::string& group, const std::string& value,
                             const std::string& source, uint64_t offset, bool hasOffset) {
    std::string key;
    key.reserve(group.size() + value.size() + source.size() + 24);
    key += group; key.push_back('\0');
    key += value; key.push_back('\0');
    key += source;
    if (hasOffset) { key.push_back('\0'); key += std::to_string(offset); }
    return key;
}
inline std::string findingKey(const Finding& f) {
    return findingKey(f.group, f.value, f.source, f.offset, f.hasOffset);
}

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
        {"fileurl",  "Download URL",  R"([A-Za-z0-9._~:/?#@!$&'()*+,;=%\-]{2,}\.(?:exe|msi|zip|7z|rar|gz|tgz|tar|bz2|xz|dmg|pkg|app|iso|deb|rpm|apk|cab|jar|whl|nupkg|vsix|appimage|bin|run)\b)"},
    };
    return p;
}

class RegexError : public std::runtime_error {
public:
    explicit RegexError(const std::string& what) : std::runtime_error(what) {}
};

struct Sink {
    std::vector<Finding> items;
    std::unordered_set<std::string> seen;
    void add(const std::string& value, Enc enc, const std::string& source, const std::string& group,
             uint64_t offset = 0, bool hasOffset = false, std::string before = {},
             std::string after = {}, std::vector<std::pair<std::string, std::string>> captures = {}) {
        if (!seen.insert(findingKey(group, value, source, offset, hasOffset)).second) return;
        items.push_back({value, enc, source, group, offset, hasOffset,
                         std::move(before), std::move(after), std::move(captures)});
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
    uint32_t val = 0; int bits = 0;
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
                         std::vector<std::string>& out, std::vector<std::size_t>* offsets = nullptr) {
    std::size_t i = 0;
    while (i < n) {
        while (i < n && !isPrintable(d[i])) ++i;
        const std::size_t start = i;
        while (i < n && isPrintable(d[i])) ++i;
        if (i - start >= minRun) {
            out.emplace_back(reinterpret_cast<const char*>(d + start), i - start);
            if (offsets) offsets->push_back(start);
        }
    }
}
inline void extractUtf16(const uint8_t* d, std::size_t n, bool le, std::size_t minRun,
                         std::vector<std::string>& out, std::vector<std::size_t>* offsets = nullptr) {
    std::string cur;
    std::size_t start = 0;
    for (std::size_t i = 0; i + 1 < n; i += 2) {
        uint8_t lo = le ? d[i] : d[i + 1];
        uint8_t hi = le ? d[i + 1] : d[i];
        if (hi == 0x00 && isPrintable(lo)) {
            if (cur.empty()) start = i;
            cur.push_back(char(lo));
        } else {
            if (cur.size() >= minRun) {
                out.push_back(cur);
                if (offsets) offsets->push_back(start);
            }
            cur.clear();
        }
    }
    if (cur.size() >= minRun) {
        out.push_back(cur);
        if (offsets) offsets->push_back(start);
    }
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

inline bool isHostChar(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-';
}

/* host.tld with a real TLD, a dotted IPv4, or localhost. everything else is a
   ://-shaped byte run, not a URL. */
inline bool plausibleHost(const std::string& h) {
    if (h.size() < 4 || h.size() > 253) return false;
    if (h == "localhost") return true;
    std::vector<std::string> labels;
    std::size_t i = 0;
    for (;;) {
        std::size_t dot = h.find('.', i);
        std::string lab = h.substr(i, (dot == std::string::npos ? h.size() : dot) - i);
        if (lab.empty() || lab.size() > 63 || lab.front() == '-' || lab.back() == '-') return false;
        for (char c : lab) if (!isHostChar(c)) return false;
        labels.push_back(lab);
        if (dot == std::string::npos) break;
        i = dot + 1;
    }
    if (labels.size() < 2) return false;
    bool numeric = true;
    for (auto& lab : labels) for (char c : lab) if (c < '0' || c > '9') { numeric = false; break; }
    if (numeric) {
        if (labels.size() != 4) return false;
        for (auto& lab : labels) {
            if (lab.size() > 3) return false;
            int v = 0; for (char c : lab) v = v * 10 + (c - '0');
            if (v > 255) return false;
        }
        return true;
    }
    const std::string& tld = labels.back();
    if (tld.size() < 2) return false;
    for (char c : tld) if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))) return false;
    return true;
}

inline bool endsWith(const std::string& s, const std::string& suf) {
    return s.size() >= suf.size() && s.compare(s.size() - suf.size(), suf.size(), suf) == 0;
}

/* obvious noise: placeholder hosts, reserved TLDs, and the XML/namespace domains
   that flood a memory dump. host is already lowercased and plausible. */
inline bool looksCrap(const std::string& h) {
    static const char* exact[] = {
        "example.com", "example.org", "example.net", "example.edu",
        "localhost", "127.0.0.1", "0.0.0.0", "domain.com", "test.com",
        "www.w3.org", "w3.org", "purl.org", "xml.org", "java.sun.com",
    };
    for (const char* e : exact) if (h == e) return true;
    static const char* nsSuffix[] = {
        ".w3.org", ".xmlsoap.org", "schemas.microsoft.com", "schemas.android.com",
        ".openxmlformats.org", ".docbook.org", "ns.adobe.com", "iptc.org",
    };
    for (const char* s : nsSuffix) if (endsWith(h, s)) return true;
    static const char* tld[] = { ".local", ".localhost", ".example", ".test",
                                 ".invalid", ".lan", ".internal", ".arpa" };
    for (const char* t : tld) if (endsWith(h, t)) return true;
    return false;
}

} // namespace detail

class Detector {
public:
    static std::pair<std::string, std::vector<std::pair<std::size_t, std::string>>>
    namedGroups(const std::string& pattern) {
        std::string result;
        std::vector<std::pair<std::size_t, std::string>> names;
        std::size_t group = 0;
        bool inClass = false;
        for (std::size_t i = 0; i < pattern.size(); ++i) {
            char c = pattern[i];
            if (c == '\\' && i + 1 < pattern.size()) {
                result += c; result += pattern[++i]; continue;
            }
            if (c == '[') inClass = true;
            if (c == ']') inClass = false;
            if (c == '(' && !inClass) {
                if (pattern.compare(i, 3, "(?<") == 0) {
                    auto end = pattern.find('>', i + 3);
                    if (end == std::string::npos) throw RegexError("named group has no closing >");
                    auto name = pattern.substr(i + 3, end - i - 3);
                    if (name.empty() || !(std::isalpha(static_cast<unsigned char>(name[0])) || name[0] == '_'))
                        throw RegexError("invalid named group");
                    for (char ch : name)
                        if (!std::isalnum(static_cast<unsigned char>(ch)) && ch != '_')
                            throw RegexError("invalid named group");
                    names.push_back({++group, name});
                    result += '('; i = end; continue;
                }
                if (pattern.compare(i, 2, "(?") != 0) ++group;
            }
            result += c;
        }
        return {result, names};
    }

    explicit Detector(Options opt) : opt_(std::move(opt)) {
        urlMode_ = (opt_.mode == Mode::Urls);
        if (!urlMode_) {
            auto flags = std::regex::ECMAScript | std::regex::optimize;
#ifdef __GLIBCXX__
            // libstdc++ otherwise chooses its recursive DFS executor. A long
            // printable process-memory run can overflow a worker's stack.
            // Polynomial mode selects its queue-based executor and rejects
            // backreferences, which cannot be evaluated with that guarantee.
            flags |= std::regex_constants::__polynomial;
#endif
            if (opt_.caseInsensitive) flags |= std::regex::icase;
            auto compile = [&](const std::string& pattern, const std::string& label) {
                if (pattern.size() > 512)
                    throw RegexError(label + ": regex exceeds the 512-byte safety limit");
                try { matchers_.emplace_back(pattern, flags); }
                catch (const std::regex_error& e) { throw RegexError(label + ": " + e.what()); }
            };
            for (const auto& id : opt_.presets)
                for (const auto& p : builtinPresets())
                    if (p.id == id) {
                        compile(p.pattern, "preset " + id);
                        names_.push_back(p.label);
                        captures_.emplace_back();
                        hints_.push_back(id == "email" ? '@' : id == "ipv4" || id == "fileurl" ? '.' :
                                         id == "ipv6" ? ':' : id == "guid" ? '-' :
                                         id == "filepath" ? '\\' : '\0');
                    }
            if (!opt_.customRegex.empty()) {
                auto [plain, names] = namedGroups(opt_.customRegex);
                std::string pat = opt_.customWholeWord ? ("\\b(?:" + plain + ")\\b") : plain;
                compile(pat, "custom regex");
                names_.push_back(opt_.customLabel.empty() ? "Custom" : opt_.customLabel);
                captures_.push_back(std::move(names));
                hints_.push_back('\0');
            }
            for (const auto& [label, pattern] : opt_.extraPatterns) {
                auto [plain, names] = namedGroups(pattern);
                compile(plain, label);
                names_.push_back(label); captures_.push_back(std::move(names));
                hints_.push_back('\0');
            }
            if (matchers_.empty()) throw RegexError("no pattern selected");
        }
    }

    bool urlMode() const { return urlMode_; }

    void testText(const std::string& text, Sink& sink) const {
        std::size_t start = 0;
        while (start <= text.size()) {
            auto end = text.find('\n', start);
            auto line = text.substr(start, end == std::string::npos ? end : end - start);
            if (!line.empty() && line.back() == '\r') line.pop_back();
            match(line, Enc::Ascii, "Sample", sink);
            if (end == std::string::npos) break;
            start = end + 1;
        }
    }

    void scan(const uint8_t* data, std::size_t n, const std::string& source, Sink& sink,
              uint64_t baseOffset = 0, bool knownOffset = false) const {
        std::vector<std::string> ascii;
        std::vector<std::size_t> asciiOffsets;
        if (opt_.ascii || opt_.base64 || opt_.hex)
            detail::extractAscii(data, n, opt_.minRun, ascii, &asciiOffsets);
        if (opt_.ascii) for (std::size_t i = 0; i < ascii.size(); ++i)
            match(ascii[i], Enc::Ascii, source, sink, baseOffset + asciiOffsets[i], knownOffset);

        std::vector<std::string> wide;
        std::vector<std::size_t> wideOffsets;
        if (opt_.utf16) {
            detail::extractUtf16(data, n, true, opt_.minRun, wide, &wideOffsets);
            detail::extractUtf16(data, n, false, opt_.minRun, wide, &wideOffsets);
            for (std::size_t i = 0; i < wide.size(); ++i)
                match(wide[i], Enc::Utf16, source, sink, baseOffset + wideOffsets[i], knownOffset, 2);
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

    void match(const std::string& s, Enc enc, const std::string& source, Sink& sink,
               uint64_t runOffset = 0, bool knownOffset = false, std::size_t stride = 1) const {
        if (s.size() > opt_.maxCandidate) return;
        if (urlMode_) matchUrls(s, enc, source, sink, runOffset, knownOffset, stride);
        else matchRegex(s, enc, source, sink, runOffset, knownOffset, stride);
    }

    void matchUrls(const std::string& s, Enc enc, const std::string& source, Sink& sink,
                   uint64_t runOffset, bool knownOffset, std::size_t stride) const {
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
            std::string host = detail::urlHost(url);
            if (url.size() >= 8 && detail::plausibleHost(host) &&
                !(opt_.dropCrap && detail::looksCrap(host)) &&
                (opt_.schemes.empty() ||
                 std::find(opt_.schemes.begin(), opt_.schemes.end(), scheme) != opt_.schemes.end()))
                sink.add(url, enc, source, host, runOffset + start * stride, knownOffset,
                         s.substr(start > 32 ? start - 32 : 0, std::min<std::size_t>(32, start)),
                         s.substr(start + url.size(), 32));
            pos = end;
        }
    }

    void matchRegex(const std::string& s, Enc enc, const std::string& source, Sink& sink,
                    uint64_t runOffset, bool knownOffset, std::size_t stride) const {
        // Bound each regex invocation independently of the printable-run size.
        // Overlapping windows preserve ordinary matches crossing a boundary,
        // while preventing long homogeneous process-memory strings from making
        // even the polynomial executor needlessly expensive.
        constexpr std::size_t window = 1024, step = 512;
        for (std::size_t i = 0; i < matchers_.size(); ++i) {
            for (std::size_t base = 0; base < s.size(); base += step) {
                const std::size_t limit = std::min(s.size(), base + window);
                if (hints_[i] && std::find(s.begin() + base, s.begin() + limit, hints_[i]) == s.begin() + limit) {
                    if (limit == s.size()) break;
                    continue;
                }
                auto flags = std::regex_constants::match_default;
                if (base) flags |= std::regex_constants::match_prev_avail;
                if (limit < s.size()) flags |= std::regex_constants::match_not_eol |
                                               std::regex_constants::match_not_eow;
                auto begin = std::sregex_iterator(s.begin() + base, s.begin() + limit,
                                                  matchers_[i], flags);
                auto end = std::sregex_iterator();
                for (auto it = begin; it != end; ++it) {
                    std::string v = it->str();
                    auto pos = base + static_cast<std::size_t>(it->position());
                    // Only the first half of a non-final window owns its
                    // matches. The overlap supplies context for the next one.
                    if (!v.empty() && v.size() <= step &&
                        (!base || pos != base) &&
                        (limit == s.size() || pos <= base + step)) {
                        std::vector<std::pair<std::string, std::string>> captures;
                        for (const auto& [index, name] : captures_[i])
                            if (index < it->size() && (*it)[index].matched)
                                captures.push_back({name, (*it)[index].str()});
                        sink.add(v, enc, source, names_[i], runOffset + pos * stride, knownOffset,
                                 s.substr(pos > 32 ? pos - 32 : 0, std::min<std::size_t>(32, pos)),
                                 s.substr(pos + v.size(), 32), std::move(captures));
                    }
                }
                if (limit == s.size()) break;
            }
        }
    }

    Options opt_;
    bool urlMode_ = true;
    std::vector<std::regex> matchers_;
    std::vector<std::string> names_;
    std::vector<std::vector<std::pair<std::size_t, std::string>>> captures_;
    std::vector<char> hints_; // required delimiters in selected built-in patterns
};

inline std::vector<Group> mergeSinks(std::vector<Sink>& sinks) {
    std::unordered_set<std::string> seen;
    std::unordered_map<std::string, std::size_t> groupIndex;
    std::vector<Group> groups;
    for (auto& sk : sinks) {
        for (auto& f : sk.items) {
            if (!seen.insert(findingKey(f)).second) continue;
            auto [it, inserted] = groupIndex.try_emplace(f.group, groups.size());
            if (inserted) groups.push_back({f.group, {}});
            groups[it->second].items.push_back(std::move(f));
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
