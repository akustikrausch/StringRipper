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

enum class Enc { Ascii, Utf16, Base64, Hex, Escaped };

inline const char* encName(Enc e) {
    switch (e) {
        case Enc::Ascii:   return "ASCII";
        case Enc::Utf16:   return "UTF-16";
        case Enc::Base64:  return "Base64";
        case Enc::Hex:     return "Hex";
        case Enc::Escaped: return "Escaped";
    }
    return "?";
}

enum class Mode { Urls, Regex };

struct Options {
    bool ascii  = true;
    bool utf16  = true;
    bool base64 = true;
    bool hex    = true;
    bool escaped = true;                /* %XX, \/, \xXX, \uXXXX inside text runs */
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

inline bool isAsciiLetter(uint32_t c) { uint32_t l = c | 0x20; return l >= 'a' && l <= 'z'; }
inline bool isLatinLetter(uint32_t c) { return c >= 0xC0 && c <= 0x24F && c != 0xD7 && c != 0xF7; }

inline void putUtf8(std::string& o, uint32_t c) {
    if (c < 0x80) o += char(c);
    else if (c < 0x800) { o += char(0xC0 | (c >> 6)); o += char(0x80 | (c & 63)); }
    else if (c < 0x10000) { o += char(0xE0 | (c >> 12)); o += char(0x80 | ((c >> 6) & 63)); o += char(0x80 | (c & 63)); }
    else { o += char(0xF0 | (c >> 18)); o += char(0x80 | ((c >> 12) & 63));
           o += char(0x80 | ((c >> 6) & 63)); o += char(0x80 | (c & 63)); }
}

/* strict UTF-8 text character at d[i]: 2..4 bytes, U+00A0 and up. 0 = not one. */
inline std::size_t utf8Char(const uint8_t* d, std::size_t n, std::size_t i, uint32_t& cp) {
    uint8_t b = d[i]; std::size_t len; uint32_t c, lo;
    if (b >= 0xC2 && b <= 0xDF) { len = 2; c = b & 0x1F; lo = 0x80; }
    else if (b >= 0xE0 && b <= 0xEF) { len = 3; c = b & 0x0F; lo = 0x800; }
    else if (b >= 0xF0 && b <= 0xF4) { len = 4; c = b & 0x07; lo = 0x10000; }
    else return 0;
    if (i + len > n) return 0;
    for (std::size_t k = 1; k < len; ++k) {
        if ((d[i + k] & 0xC0) != 0x80) return 0;
        c = (c << 6) | (d[i + k] & 0x3F);
    }
    if (c < lo || c < 0xA0 || c > 0x10FFFF || (c >= 0xD800 && c <= 0xDFFF) ||
        c == 0xFEFF || (c & 0xFFFE) == 0xFFFE) return 0;
    cp = c; return len;
}

inline bool isWordEdge(uint32_t c) {
    switch (c) {
        case ' ': case '\\': case '/': case '_': case '-': case '.': case ',': case ':': case ';':
        case '(': case ')': case '[': case ']': case '"': case '\'':
            return true;
        default: return false;
    }
}

/* A non-ASCII character only counts inside a word (a letter on one side, a
   letter, word edge or NUL on the other) and next to real text: the 8-bit
   extractor only looks at it around a printable stretch of at least minRun
   characters, UTF-16 asks for such a stretch beside it. Random binary is full
   of 0xC0..0xFF bytes and valid-looking UTF-8 pairs; without that anchor they
   glue three-byte junk into new runs. ANSI and UTF-16 take Latin letters (two
   in a row, as in "Größe"); UTF-8 takes any script and counts as a letter. */
struct Near8 {
    const uint8_t* d; std::size_t n;
    bool A(std::size_t j) const { return j < n && isAsciiLetter(d[j]); }
    bool E(std::size_t j) const { return j < n && isWordEdge(d[j]); }
    bool Z(std::size_t j) const { return j >= n || d[j] == 0; }
    bool Lat(std::size_t j) const { return j < n && isLatinLetter(d[j]); }
    bool mbStart(std::size_t j) const { uint32_t c; return j < n && d[j] >= 0xC2 && utf8Char(d, n, j, c); }
    bool mbEnd(std::size_t j) const {
        if (j >= n || (d[j] & 0xC0) != 0x80) return false;
        for (std::size_t b = 1; b <= 3 && b <= j; ++b)
            if ((d[j - b] & 0xC0) != 0x80) { uint32_t c; return utf8Char(d, n, j - b, c) == b + 1; }
        return false;
    }
};

/* one non-ASCII text character at d[k]: UTF-8 (2..4 bytes, taken as is) or an
   ANSI Latin letter (1 byte, becomes UTF-8). 0 = neither. */
inline std::size_t wideCharAt(const uint8_t* d, std::size_t n, std::size_t k, uint32_t& cp, bool& ansi) {
    const Near8 z{d, n};
    if (d[k] >= 0xC2 && d[k] <= 0xF4 && k + 1 < n && (d[k + 1] & 0xC0) == 0x80) {
        const std::size_t len = utf8Char(d, n, k, cp), e = k + len;
        if (!len) return 0;
        const bool before = z.A(k - 1) || z.mbEnd(k - 1), after = z.A(e) || z.mbStart(e);
        if ((before && (after || z.E(e) || z.Z(e))) || (after && (z.E(k - 1) || z.Z(k - 1)))) { ansi = false; return len; }
        return 0;
    }
    if (!isLatinLetter(d[k])) return 0;
    const bool before = z.A(k - 1) || (z.Lat(k - 1) && z.A(k - 2));
    const bool after = z.A(k + 1) || (z.Lat(k + 1) && z.A(k + 2));
    if ((before && (after || z.E(k + 1) || z.Z(k + 1))) || (after && (z.E(k - 1) || z.Z(k - 1)))) {
        cp = d[k]; ansi = true; return 1;
    }
    return 0;
}

/* 8-bit text: printable ASCII, UTF-8, and ANSI Latin letters (turned into
   UTF-8). Stretches shorter than minRun are skipped as always; a long one
   reaches over non-ASCII characters on both sides and takes in the short
   stretches beyond them ("J" + "ü" + "rgen"). Only such a run is rebuilt, and
   one holding ANSI letters gets a map from output byte to source byte so
   offsets stay exact (other bytes map one to one). */
inline void extractAscii(const uint8_t* d, std::size_t n, std::size_t minRun,
                         std::vector<std::string>& out, std::vector<std::size_t>* offsets = nullptr,
                         std::vector<std::vector<uint32_t>>* maps = nullptr) {
    std::size_t i = 0, floor = 0;
    uint32_t cp = 0; bool ansi = false;
    auto endingAt = [&](std::size_t end) -> std::size_t {
        if (end <= floor || d[end - 1] < 0x80) return 0;
        if ((d[end - 1] & 0xC0) != 0x80) return wideCharAt(d, n, end - 1, cp, ansi) == 1;
        for (std::size_t b = 2; b <= 4 && end >= floor + b; ++b)
            if ((d[end - b] & 0xC0) != 0x80) return wideCharAt(d, n, end - b, cp, ansi) == b ? b : 0;
        return 0;
    };
    while (i < n) {
        while (i < n && !isPrintable(d[i])) ++i;
        if (i >= n) break;
        const std::size_t start = i;
        while (i < n && isPrintable(d[i])) ++i;
        if (i - start < minRun) continue;
        std::size_t head = start;
        while (std::size_t b = endingAt(head)) {
            head -= b;
            while (head > floor && isPrintable(d[head - 1])) --head;
        }
        if (head == start && !(i < n && d[i] >= 0x80 && wideCharAt(d, n, i, cp, ansi))) {
            out.emplace_back(reinterpret_cast<const char*>(d + start), i - start);
            if (offsets) offsets->push_back(start);
            if (maps) maps->emplace_back();
            floor = i;
            continue;
        }
        std::string run; std::vector<uint32_t> map; bool mapped = false;
        std::size_t k = head;
        while (k < n) {
            if (isPrintable(d[k])) {
                std::size_t j = k + 1;
                while (j < n && isPrintable(d[j])) ++j;
                if (mapped) for (std::size_t q = k; q < j; ++q) map.push_back(uint32_t(q - head));
                run.append(reinterpret_cast<const char*>(d + k), j - k);
                k = j;
                continue;
            }
            const std::size_t len = d[k] >= 0x80 ? wideCharAt(d, n, k, cp, ansi) : 0;
            if (!len) break;
            if (ansi) {
                if (!mapped) { for (std::size_t q = 0; q < run.size(); ++q) map.push_back(uint32_t(q)); mapped = true; }
                std::size_t at = run.size(); putUtf8(run, cp);
                for (; at < run.size(); ++at) map.push_back(uint32_t(k - head));
            } else {
                if (mapped) for (std::size_t q = 0; q < len; ++q) map.push_back(uint32_t(k + q - head));
                run.append(reinterpret_cast<const char*>(d + k), len);
            }
            k += len;
        }
        out.push_back(std::move(run));
        if (offsets) offsets->push_back(head);
        if (maps) maps->push_back(mapped ? std::move(map) : std::vector<uint32_t>{});
        i = floor = k;
    }
}

/* UTF-16 text: printable ASCII units plus anchored Latin letters inside a
   word (same rule as ANSI). A Latin letter makes the output longer than a byte
   per unit, so that run carries a map (source byte offset per output byte). */
template <bool LE>
inline void extractUtf16Of(const uint8_t* d, std::size_t n, std::size_t minRun, std::vector<std::string>& out,
                           std::vector<std::size_t>* offsets, std::vector<std::vector<uint32_t>>* maps) {
    const std::size_t units = n / 2;
    auto u = [d](std::size_t k) -> uint32_t {
        return LE ? uint32_t(d[2 * k]) | uint32_t(d[2 * k + 1]) << 8 : uint32_t(d[2 * k + 1]) | uint32_t(d[2 * k]) << 8;
    };
    auto printable = [&](std::size_t j) { return j < units && u(j) - 0x20 <= 0x5E; };
    auto latin = [&](std::size_t k) {
        auto A = [&](std::size_t j) { return j < units && isAsciiLetter(u(j)); };
        auto E = [&](std::size_t j) { return j < units && isWordEdge(u(j)); };
        auto Z = [&](std::size_t j) { return j >= units || u(j) == 0; };
        auto C = [&](std::size_t j) { return j < units && isLatinLetter(u(j)); };
        auto runBefore = [&](std::size_t end) { std::size_t c = 0; while (c < minRun && end > c && printable(end - 1 - c)) ++c; return c >= minRun; };
        auto runFrom = [&](std::size_t at) { std::size_t c = 0; while (c < minRun && printable(at + c)) ++c; return c >= minRun; };
        const bool pairL = C(k - 1) && A(k - 2), pairR = C(k + 1) && A(k + 2);
        const bool before = A(k - 1) || pairL, after = A(k + 1) || pairR;
        const bool word = (before && (after || E(k + 1) || Z(k + 1))) || (after && (E(k - 1) || Z(k - 1)));
        return word && (runBefore(k) || runFrom(k + 1) || (pairL && runBefore(k - 1)) || (pairR && runFrom(k + 2)));
    };
    std::size_t k = 0;
    while (k < units) {
        for (; k < units; ++k) {
            const uint32_t x = u(k);
            if (x - 0x20 <= 0x5E || (isLatinLetter(x) && latin(k))) break;
        }
        if (k >= units) break;
        const std::size_t start = k;
        std::string cur; std::vector<uint32_t> map; std::size_t chars = 0; bool mapped = false;
        for (; k < units; ++k) {
            const uint32_t x = u(k);
            if (x - 0x20 <= 0x5E) {
                if (mapped) map.push_back(uint32_t(2 * (k - start)));
                cur.push_back(char(x)); ++chars;
                continue;
            }
            if (!isLatinLetter(x) || !latin(k)) break;
            if (!mapped) { for (std::size_t j = 0; j < cur.size(); ++j) map.push_back(uint32_t(2 * j)); mapped = true; }
            std::size_t at = cur.size(); putUtf8(cur, x);
            for (; at < cur.size(); ++at) map.push_back(uint32_t(2 * (k - start)));
            ++chars;
        }
        if (chars >= minRun) {
            out.push_back(std::move(cur));
            if (offsets) offsets->push_back(2 * start);
            if (maps) maps->push_back(mapped ? std::move(map) : std::vector<uint32_t>{});
        }
    }
}
inline void extractUtf16(const uint8_t* d, std::size_t n, bool le, std::size_t minRun,
                         std::vector<std::string>& out, std::vector<std::size_t>* offsets = nullptr,
                         std::vector<std::vector<uint32_t>>* maps = nullptr) {
    if (le) extractUtf16Of<true>(d, n, minRun, out, offsets, maps);
    else extractUtf16Of<false>(d, n, minRun, out, offsets, maps);
}

/* context cut at 32 bytes must not split a UTF-8 character */
inline std::string clipUtf8(std::string v) {
    std::size_t a = 0;
    while (a < v.size() && (uint8_t(v[a]) & 0xC0) == 0x80) ++a;
    v.erase(0, a);
    std::size_t k = v.size(), tail = 0;
    while (k && tail < 3 && (uint8_t(v[k - 1]) & 0xC0) == 0x80) { --k; ++tail; }
    if (k && uint8_t(v[k - 1]) >= 0xC0) {
        uint8_t l = uint8_t(v[k - 1]);
        std::size_t need = l >= 0xF0 ? 4 : l >= 0xE0 ? 3 : 2;
        if (tail + 1 < need) v.erase(k - 1);
    }
    return v;
}

inline int hexDigit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
inline int hexPair(const std::string& s, std::size_t i) {
    if (i + 1 >= s.size()) return -1;
    int a = hexDigit(s[i]), b = hexDigit(s[i + 1]);
    return (a < 0 || b < 0) ? -1 : a * 16 + b;
}

inline bool hasEscape(const std::string& s) {
    for (std::size_t i = s.find('%'); i != std::string::npos; i = s.find('%', i + 1))
        if (hexPair(s, i + 1) >= 0) return true;
    for (std::size_t i = s.find('\\'); i != std::string::npos && i + 1 < s.size(); i = s.find('\\', i + 1)) {
        const char e = s[i + 1];
        if (e == '/' || (e == 'x' && hexPair(s, i + 2) >= 0) ||
            (e == 'u' && hexPair(s, i + 2) >= 0 && hexPair(s, i + 4) >= 0)) return true;
    }
    return false;
}

/* one layer of %XX, \/, \xXX and \uXXXX (surrogate pairs joined). Per output
   byte: src = index into s, kind = 0 plain, 1 backslash escape, 2 percent. */
inline bool unescape(const std::string& s, std::string& out,
                     std::vector<uint32_t>& src, std::vector<uint8_t>& kind) {
    bool any = false;
    auto put = [&](char c, std::size_t at, uint8_t k) { out += c; src.push_back(uint32_t(at)); kind.push_back(k); };
    for (std::size_t i = 0; i < s.size();) {
        int v;
        if (s[i] == '%' && (v = hexPair(s, i + 1)) >= 0) { put(char(v), i, 2); i += 3; any = true; continue; }
        if (s[i] == '\\' && i + 1 < s.size()) {
            const char e = s[i + 1];
            if (e == '/') { put('/', i, 1); i += 2; any = true; continue; }
            if (e == 'x' && (v = hexPair(s, i + 2)) >= 0) { put(char(v), i, 1); i += 4; any = true; continue; }
            int h, l;
            if (e == 'u' && (h = hexPair(s, i + 2)) >= 0 && (l = hexPair(s, i + 4)) >= 0) {
                uint32_t c = uint32_t(h << 8 | l); std::size_t used = 6;
                if (c >= 0xD800 && c <= 0xDBFF && i + 7 < s.size() && s[i + 6] == '\\' && s[i + 7] == 'u') {
                    int h2 = hexPair(s, i + 8), l2 = hexPair(s, i + 10);
                    uint32_t lo = uint32_t(h2 << 8 | l2);
                    if (h2 >= 0 && l2 >= 0 && lo >= 0xDC00 && lo <= 0xDFFF) {
                        c = 0x10000 + ((c - 0xD800) << 10) + (lo - 0xDC00); used = 12;
                    }
                }
                if (c < 0xD800 || c > 0xDFFF) {
                    std::string u8; putUtf8(u8, c);
                    for (char ch : u8) put(ch, i, 1);
                    i += used; any = true; continue;
                }
            }
        }
        put(s[i], i, 0); ++i;
    }
    return any;
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

/* where a candidate string sits in the source: base + pos * stride, or via
   map when the text is not one byte per unit. esc marks escape-decoded bytes
   (Escaped decoder only). */
struct RunView {
    uint64_t base = 0;
    bool known = false;
    std::size_t stride = 1;
    const std::vector<uint32_t>* map = nullptr;
    const std::vector<uint8_t>* esc = nullptr;
    uint64_t at(std::size_t pos) const { return base + (map ? (*map)[pos] : pos * stride); }
};

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
                bool namedGroup = pattern.compare(i, 3, "(?<") == 0 &&
                                  i + 3 < pattern.size() &&
                                  pattern[i + 3] != '=' && pattern[i + 3] != '!';
                if (namedGroup) {
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
        auto view = [&](std::size_t off, const std::vector<uint32_t>& m, std::size_t stride) {
            return detail::RunView{baseOffset + off, knownOffset, stride, m.empty() ? nullptr : &m, nullptr};
        };
        std::vector<std::string> ascii;
        std::vector<std::size_t> asciiOffsets;
        std::vector<std::vector<uint32_t>> asciiMaps;
        if (opt_.ascii || opt_.base64 || opt_.hex || opt_.escaped)
            detail::extractAscii(data, n, opt_.minRun, ascii, &asciiOffsets, &asciiMaps);
        for (std::size_t i = 0; i < ascii.size(); ++i) {
            const detail::RunView v = view(asciiOffsets[i], asciiMaps[i], 1);
            if (opt_.ascii) match(ascii[i], Enc::Ascii, source, sink, v);
            if (opt_.escaped) matchEscaped(ascii[i], source, sink, v);
        }

        std::vector<std::string> wide;
        std::vector<std::size_t> wideOffsets;
        std::vector<std::vector<uint32_t>> wideMaps;
        if (opt_.utf16) {
            detail::extractUtf16(data, n, true, opt_.minRun, wide, &wideOffsets, &wideMaps);
            detail::extractUtf16(data, n, false, opt_.minRun, wide, &wideOffsets, &wideMaps);
            for (std::size_t i = 0; i < wide.size(); ++i) {
                const detail::RunView v = view(wideOffsets[i], wideMaps[i], 2);
                match(wide[i], Enc::Utf16, source, sink, v);
                if (opt_.escaped) matchEscaped(wide[i], source, sink, v);
            }
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

    /* JSON/JS/percent escaped text: only what the escapes hid is reported, so
       a plain URL with a %20 in its path is not found twice. */
    void matchEscaped(const std::string& s, const std::string& source, Sink& sink, const detail::RunView& rv) const {
        if (!detail::hasEscape(s)) return;
        std::string u; std::vector<uint32_t> src; std::vector<uint8_t> kind;
        if (!detail::unescape(s, u, src, kind)) return;
        std::vector<uint32_t> map(src.size());
        for (std::size_t k = 0; k < src.size(); ++k)
            map[k] = rv.map ? (*rv.map)[src[k]] : uint32_t(src[k] * rv.stride);
        match(u, Enc::Escaped, source, sink, detail::RunView{rv.base, rv.known, 1, &map, &kind});
    }

    void match(const std::string& s, Enc enc, const std::string& source, Sink& sink,
               const detail::RunView& rv = {}) const {
        if (s.size() > opt_.maxCandidate) return;
        if (urlMode_) matchUrls(s, enc, source, sink, rv);
        else matchRegex(s, enc, source, sink, rv);
    }

    void matchUrls(const std::string& s, Enc enc, const std::string& source, Sink& sink,
                   const detail::RunView& rv) const {
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
            bool emit = !rv.esc;
            if (rv.esc) {
                const auto& k = *rv.esc;
                for (std::size_t q = pos; q < pos + 3; ++q) emit |= k[q] != 0;
                for (std::size_t q = start; !emit && q < start + url.size(); ++q) emit |= k[q] == 1;
            }
            if (emit && url.size() >= 8 && detail::plausibleHost(host) &&
                !(opt_.dropCrap && detail::looksCrap(host)) &&
                (opt_.schemes.empty() ||
                 std::find(opt_.schemes.begin(), opt_.schemes.end(), scheme) != opt_.schemes.end()))
                sink.add(url, enc, source, host, rv.at(start), rv.known,
                         detail::clipUtf8(s.substr(start > 32 ? start - 32 : 0, std::min<std::size_t>(32, start))),
                         detail::clipUtf8(s.substr(start + url.size(), 32)));
            pos = end;
        }
    }

    void matchRegex(const std::string& s, Enc enc, const std::string& source, Sink& sink,
                    const detail::RunView& rv) const {
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
                std::sregex_iterator it, end;
                try {
                    it = std::sregex_iterator(s.begin() + base, s.begin() + limit, matchers_[i], flags);
                } catch (const std::regex_error&) {
                    if (limit == s.size()) break;
                    continue;
                }
                for (; it != end; ) {
                    std::string v = it->str();
                    auto pos = base + static_cast<std::size_t>(it->position());
                    bool emit = !rv.esc;
                    for (std::size_t q = pos; !emit && q < pos + v.size(); ++q) emit = (*rv.esc)[q] != 0;
                    if (emit && !v.empty() && v.size() <= step &&
                        (!base || pos != base) &&
                        (limit == s.size() || pos <= base + step)) {
                        std::vector<std::pair<std::string, std::string>> captures;
                        for (const auto& [index, name] : captures_[i])
                            if (index < it->size() && (*it)[index].matched)
                                captures.push_back({name, (*it)[index].str()});
                        sink.add(v, enc, source, names_[i], rv.at(pos), rv.known,
                                 detail::clipUtf8(s.substr(pos > 32 ? pos - 32 : 0, std::min<std::size_t>(32, pos))),
                                 detail::clipUtf8(s.substr(pos + v.size(), 32)), std::move(captures));
                    }
                    try { ++it; } catch (const std::regex_error&) { break; }
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
