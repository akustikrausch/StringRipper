// test_scan.cpp - portable self-test for the StringRipper detection core.
// Build (any platform): c++ -std=c++20 -I../src test_scan.cpp -o test_scan
#include "../src/scan_core.hpp"

#include <cassert>
#include <cstdio>
#include <string>
#include <vector>

static int failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { std::printf("FAIL: %s\n", msg); ++failures; } \
                              else std::printf("ok:   %s\n", msg); } while (0)

static std::string b64(const std::string& in) {
    static const char* T = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out; uint32_t val = 0; int bits = -6;
    for (unsigned char c : in) { val = (val << 8) + c; bits += 8;
        while (bits >= 0) { out.push_back(T[(val >> bits) & 0x3F]); bits -= 6; } }
    if (bits > -6) out.push_back(T[((val << 8) >> (bits + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}
static std::string hex(const std::string& in) {
    static const char* H = "0123456789abcdef"; std::string o;
    for (unsigned char c : in) { o.push_back(H[c >> 4]); o.push_back(H[c & 0xF]); }
    return o;
}
static void appendAscii(std::vector<uint8_t>& b, const std::string& s) {
    b.push_back(0); for (char c : s) b.push_back((uint8_t)c); b.push_back(0);
}
static void appendUtf16le(std::vector<uint8_t>& b, const std::string& s) {
    b.push_back(0); b.push_back(0);
    for (char c : s) { b.push_back((uint8_t)c); b.push_back(0); }
    b.push_back(0); b.push_back(0);
}

static bool hasGroup(const std::vector<ur::Group>& g, const std::string& name) {
    for (auto& x : g) { if (x.name == name) return true; }
    return false;
}
static bool hasValue(const std::vector<ur::Group>& g, const std::string& v) {
    for (auto& x : g) { for (auto& f : x.items) { if (f.value == v) return true; } }
    return false;
}
// Run the detector over a buffer and return merged groups.
static std::vector<ur::Group> run(const ur::Options& o, const std::vector<uint8_t>& buf) {
    ur::Detector det(o);
    ur::Sink sink;
    det.scan(buf.data(), buf.size(), "test", sink);
    std::vector<ur::Sink> sinks;
    sinks.push_back(std::move(sink));
    return ur::mergeSinks(sinks);
}

int main() {
    {
        std::vector<uint8_t> b;
        appendAscii(b, "https://plain.example.com/x");
        appendAscii(b, b64("https://encoded.example.com/x"));
        ur::Options o; o.ascii = false; o.utf16 = false; o.hex = false;
        auto g = run(o, b);
        CHECK(!hasGroup(g, "plain.example.com"), "disabled ASCII does not emit direct matches");
        CHECK(hasGroup(g, "encoded.example.com"), "Base64 still scans ASCII containers");
        o.base64 = false;
        CHECK(run(o, b).empty(), "all decoders disabled yields no findings");
    }
    std::vector<uint8_t> buf;
    appendAscii(buf, "https://api.example.com/v1/devices");
    appendUtf16le(buf, "https://wide.example.org/path?q=1");
    appendAscii(buf, "junk " + b64("http://b64.example.net/hidden") + " junk");
    appendAscii(buf, "prefix" + hex("https://hex.example.io/a") + "suffix");
    appendAscii(buf, "contact telemetry@mail.example.com now");
    appendAscii(buf, "AKIA1234567890ABCDEF is a key");

    // URL mode
    {
        ur::Options o; o.mode = ur::Mode::Urls;
        auto g = run(o, buf);
        CHECK(hasGroup(g, "api.example.com"), "url ascii domain");
        CHECK(hasGroup(g, "wide.example.org"), "url utf-16 domain");
        CHECK(hasGroup(g, "b64.example.net"), "url base64 domain");
        CHECK(hasGroup(g, "hex.example.io"), "url hex domain");
        // sorted Z to A: first group name >= last
        CHECK(g.size() >= 4 && g.front().name >= g.back().name, "groups sorted descending");
        // base64 finding carries the Base64 encoding label
        bool b64enc = false;
        for (auto& x : g) for (auto& f : x.items)
            if (f.group == "b64.example.net" && f.enc == ur::Enc::Base64) b64enc = true;
        CHECK(b64enc, "base64 finding labelled Base64");
    }

    // false positives: :// without a real host is skipped
    {
        std::vector<uint8_t> b;
        appendAscii(b, "http://nothing");             // no dot
        appendAscii(b, "http://a.b");                 // 1-char tld
        appendAscii(b, "http://256.1.1.1/x");         // not a valid ipv4
        appendAscii(b, "http://1.2.3.4/ok");          // ipv4 ok
        appendAscii(b, "https://real.example.com/ok");// ok
        ur::Options o;
        auto g = run(o, b);
        CHECK(!hasGroup(g, "nothing"), "host without dot skipped");
        CHECK(!hasGroup(g, "a.b"), "one-char tld skipped");
        CHECK(!hasGroup(g, "256.1.1.1"), "bad ipv4 skipped");
        CHECK(hasGroup(g, "1.2.3.4"), "ipv4 host kept");
        CHECK(hasGroup(g, "real.example.com"), "valid host kept");
        CHECK(g.size() == 2, "only the two valid hosts");
    }

    // Regex mode: email + AWS key
    {
        ur::Options o; o.mode = ur::Mode::Regex; o.presets = {"email", "apikey"};
        auto g = run(o, buf);
        CHECK(hasValue(g, "telemetry@mail.example.com"), "regex email match");
        CHECK(hasValue(g, "AKIA1234567890ABCDEF"), "regex aws key match");
    }

    // De-dup: same URL twice -> one finding
    {
        std::vector<uint8_t> two;
        appendAscii(two, "https://dup.example.com/x");
        appendAscii(two, "https://dup.example.com/x");
        ur::Options o;
        auto g = run(o, two);
        std::size_t n = 0; for (auto& x : g) n += x.items.size();
        CHECK(n == 1, "duplicate url collapsed to one");
    }

    // A match in another source is a distinct navigable occurrence; overlapping
    // windows of the same source/offset still collapse.
    {
        std::vector<uint8_t> one;
        appendAscii(one, "https://merge.example.com/a");
        ur::Options o;
        ur::Detector det(o);
        ur::Sink s1, s2;
        det.scan(one.data(), one.size(), "t1", s1);
        det.scan(one.data(), one.size(), "t2", s2);
        std::vector<ur::Sink> sinks; sinks.push_back(std::move(s1)); sinks.push_back(std::move(s2));
        auto g = ur::mergeSinks(sinks);
        CHECK(ur::countFindings(g) == 2, "distinct sources retain their own findings");
        ur::Sink s3, s4;
        det.scan(one.data(), one.size(), "same", s3, 10, true);
        det.scan(one.data(), one.size(), "same", s4, 10, true);
        std::vector<ur::Sink> overlap; overlap.push_back(std::move(s3)); overlap.push_back(std::move(s4));
        CHECK(ur::countFindings(ur::mergeSinks(overlap)) == 1, "same source offset is deduplicated");
    }

    // Crap filter drops namespace/reserved hosts by default, keeps them when off
    {
        std::vector<uint8_t> b;
        appendAscii(b, "ns http://www.w3.org/2000/svg and https://good.ripper.dev/x here");
        ur::Options on; ur::Detector d1(on);
        ur::Sink s1; d1.scan(b.data(), b.size(), "t", s1);
        std::vector<ur::Sink> v1; v1.push_back(std::move(s1));
        auto g1 = ur::mergeSinks(v1);
        CHECK(!hasGroup(g1, "www.w3.org") && hasGroup(g1, "good.ripper.dev"),
              "crap filter drops w3.org, keeps real host");

        ur::Options off; off.dropCrap = false; ur::Detector d2(off);
        ur::Sink s2; d2.scan(b.data(), b.size(), "t", s2);
        std::vector<ur::Sink> v2; v2.push_back(std::move(s2));
        auto g2 = ur::mergeSinks(v2);
        CHECK(hasGroup(g2, "www.w3.org"), "crap filter off keeps w3.org");
    }

    // Download-URL preset matches a bare path ending in an installer extension
    {
        std::vector<uint8_t> b;
        appendAscii(b, "path /plugins/AmpliTube5/AmpliTube_5_10_9.zip end");
        ur::Options o; o.mode = ur::Mode::Regex; o.presets = {"fileurl"};
        ur::Detector det(o); ur::Sink s; det.scan(b.data(), b.size(), "t", s);
        std::vector<ur::Sink> v; v.push_back(std::move(s));
        auto g = ur::mergeSinks(v);
        CHECK(hasValue(g, "/plugins/AmpliTube5/AmpliTube_5_10_9.zip"),
              "fileurl preset matches partial path");
    }

    // Bad custom regex -> throws
    {
        bool threw = false;
        try { ur::Options o; o.mode = ur::Mode::Regex; o.customRegex = "("; ur::Detector det(o); }
        catch (const ur::RegexError&) { threw = true; }
        CHECK(threw, "invalid custom regex rejected");
    }

    // windowed regex: long run, window border, anchors, oversize hit
    {
        ur::Options o; o.mode = ur::Mode::Regex;
        o.presets = {"email", "ipv4", "ipv6", "guid", "apikey", "filepath", "fileurl"};
        std::string data(7000, 'A');
        data += " contact@example.org ";
        ur::Detector det(o); ur::Sink sink;
        det.scan(reinterpret_cast<const uint8_t*>(data.data()), data.size(), "long", sink);
        CHECK(!sink.items.empty(), "long process-memory run scans without stack overflow");
        CHECK(sink.items[0].value == "contact@example.org", "long run retains regex result");
    }
    {
        ur::Options o; o.mode = ur::Mode::Regex; o.customRegex = "TKT-[0-9]{6}";
        std::string data(508, 'A'); data += "TKT-123456"; data += std::string(530, 'B');
        ur::Detector det(o); ur::Sink sink;
        det.scan(reinterpret_cast<const uint8_t*>(data.data()), data.size(), "boundary", sink, 100, true);
        CHECK(sink.items.size() == 1, "cross-window regex match is deduplicated");
        CHECK(!sink.items.empty() && sink.items[0].offset == 608,
              "cross-window regex match retains absolute offset");
    }
    {
        ur::Options o; o.mode = ur::Mode::Regex; o.customRegex = "^TKT-[0-9]{6}$";
        std::string data(512, 'A'); data += "TKT-123456"; data += std::string(512, 'B');
        ur::Detector det(o); ur::Sink sink;
        det.scan(reinterpret_cast<const uint8_t*>(data.data()), data.size(), "anchors", sink);
        CHECK(sink.items.empty(), "window boundaries do not create anchored matches");
    }
    {
        ur::Options o; o.mode = ur::Mode::Regex; o.customRegex = "A+";
        std::string data(1500, 'A');
        ur::Detector det(o); ur::Sink sink;
        det.scan(reinterpret_cast<const uint8_t*>(data.data()), data.size(), "long-value", sink);
        CHECK(sink.items.empty(), "oversize match does not emit a truncated suffix");
    }
#ifdef __GLIBCXX__
    {
        bool rejected = false;
        try { ur::Options o; o.mode = ur::Mode::Regex; o.customRegex = R"((a)\1)"; ur::Detector det(o); }
        catch (const ur::RegexError&) { rejected = true; }
        CHECK(rejected, "unsafe backreference rejected before scanning");
    }
#endif

    {
        ur::Options o; o.mode = ur::Mode::Regex;
        o.customRegex = R"(ID-(?<site>[A-Z]+)-(?<serial>[0-9]+))";
        ur::Detector d(o); ur::Sink sink;
        const std::string data = "---- ID-ABC-42 ----";
        d.scan(reinterpret_cast<const uint8_t*>(data.data()), data.size(), "file", sink, 100, true);
        CHECK(sink.items.size() == 1, "named regex group matches");
        if (!sink.items.empty()) {
            const auto& f = sink.items[0];
            CHECK(f.hasOffset && f.offset == 105, "direct match has exact absolute offset");
            CHECK(f.before == "---- " && f.after == " ----", "match context retained");
            CHECK(f.captures.size() == 2 && f.captures[0].first == "site" &&
                  f.captures[0].second == "ABC" && f.captures[1].first == "serial" &&
                  f.captures[1].second == "42", "named groups retained");
        }
    }

    // Regression: lookbehind was reported as a malformed named group
    {
        auto rejectsAsLookbehind = [](const std::string& pattern) {
            try { ur::Options o; o.mode = ur::Mode::Regex; o.customRegex = pattern; ur::Detector d(o); return false; }
            catch (const ur::RegexError& e) {
                std::string w = e.what();
                return w.find("named group") == std::string::npos;
            }
        };
        CHECK(rejectsAsLookbehind("(?<=foo)bar"), "lookbehind rejected on its own terms, not as a bad named group");
        CHECK(rejectsAsLookbehind("(?<!foo)bar"), "negative lookbehind rejected on its own terms, not as a bad named group");
        ur::Options o; o.mode = ur::Mode::Regex; o.customRegex = "(?<id>[0-9]+)";
        bool ok = true;
        try { ur::Detector d(o); } catch (const ur::RegexError&) { ok = false; }
        CHECK(ok, "named group still parses after the lookbehind fix");
    }

    // umlauts: UTF-8, ANSI (cp1252) and UTF-16 keep the whole path, offsets stay exact
    {
        auto one = [](const std::vector<ur::Group>& g, const std::string& v) -> const ur::Finding* {
            for (auto& x : g) for (auto& f : x.items) if (f.value == v) return &f;
            return nullptr;
        };
        auto bytes = [](const std::string& s) { return std::vector<uint8_t>(s.begin(), s.end()); };
        ur::Options path; path.mode = ur::Mode::Regex; path.presets = {"filepath"};
        ur::Options app; app.mode = ur::Mode::Regex; app.customRegex = "AppData";

        auto g8 = run(path, bytes(std::string("\x01" "C:\\Users\\J\xC3\xBCrgen\\cfg.ini\x01")));
        auto* f8 = one(g8, "C:\\Users\\J\xC3\xBCrgen\\cfg.ini");
        CHECK(f8 && f8->offset == 1, "UTF-8 umlaut path kept whole, exact offset");

        const std::string ansiPath = std::string("\x01" "C:\\Users\\J\xFCrgen\\AppData\\x.txt\x01");
        auto ga = run(path, bytes(ansiPath));
        CHECK(one(ga, "C:\\Users\\J\xC3\xBCrgen\\AppData\\x.txt"), "ANSI umlaut path kept whole, as UTF-8");
        auto gaApp = run(app, bytes(ansiPath));
        auto* fa = one(gaApp, "AppData");
        CHECK(fa && fa->offset == ansiPath.find("AppData"), "offset after an ANSI umlaut maps to the source byte");

        auto gs = run(path, bytes(std::string("\x01" "C:\\Users\\\xC4rger\\Gr\xF6\xDF" "e.txt\x01")));
        CHECK(one(gs, "C:\\Users\\\xC3\x84rger\\Gr\xC3\xB6\xC3\x9F" "e.txt"), "ANSI word start and two-letter cluster kept");

        ur::Options word; word.mode = ur::Mode::Regex; word.customRegex = "[^ ]+";
        auto gj = run(word, bytes(std::string("\x01\xE4\xF6\xFC\xE4 \xE9 1\xFC" "2 plain text\x01")));
        bool glued = false;
        for (auto& x : gj) for (auto& f : x.items) glued |= f.value.find('\xC3') != std::string::npos;
        CHECK(!gj.empty() && !glued, "high bytes without letters around do not glue into the run");

        std::vector<uint8_t> w;
        const std::string wide = "C:\\Users\\J\xFCrgen\\AppData\\x.txt";
        w.push_back(0); w.push_back(0);
        for (unsigned char c : wide) { w.push_back(c); w.push_back(0); }
        w.push_back(0); w.push_back(0);
        auto gw = run(path, w);
        auto* fw = one(gw, "C:\\Users\\J\xC3\xBCrgen\\AppData\\x.txt");
        CHECK(fw && fw->enc == ur::Enc::Utf16 && fw->offset == 2, "UTF-16 umlaut path kept whole, exact offset");
        auto gwApp = run(app, w);
        auto* fwa = one(gwApp, "AppData");
        CHECK(fwa && fwa->offset == 2 + 2 * wide.find("AppData"), "UTF-16 offset after an umlaut maps to the source unit");
    }

    // escaped URLs: JSON \/, percent, \u002F and \x2F; nothing twice
    {
        auto bytes = [](const std::string& s) { return std::vector<uint8_t>(s.begin(), s.end()); };
        auto only = [](const std::vector<ur::Group>& g, const std::string& v) {
            std::size_t n = 0; const ur::Finding* hit = nullptr;
            for (auto& x : g) for (auto& f : x.items) if (f.value == v) { ++n; hit = &f; }
            return n == 1 ? hit : nullptr;
        };
        ur::Options o;
        const std::string json = "\x01{\"u\":\"https:\\/\\/cdn.example.com\\/app.zip\"}\x01";
        auto* fj = only(run(o, bytes(json)), "https://cdn.example.com/app.zip");
        CHECK(fj && fj->enc == ur::Enc::Escaped && fj->offset == json.find("https"), "JSON-escaped URL found, exact offset");

        const std::string pct = "\x01next=https%3A%2F%2Fcdn.example.com%2Fa.zip\x01";
        auto* fp = only(run(o, bytes(pct)), "https://cdn.example.com/a.zip");
        CHECK(fp && fp->offset == pct.find("https"), "percent-encoded URL found, exact offset");

        CHECK(only(run(o, bytes("\x01https:\\u002F\\u002Fu.example.com\\u002Fx\x01")), "https://u.example.com/x"),
              "\\u002F-escaped URL found");
        CHECK(only(run(o, bytes("\x01https:\\x2F\\x2Fx.example.com\\x2Fy\x01")), "https://x.example.com/y"),
              "\\x2F-escaped URL found");

        auto plain = run(o, bytes("\x01https://p.example.com/my%20file.zip\x01"));
        CHECK(ur::countFindings(plain) == 1, "plain URL with %20 in the path is not reported twice");

        ur::Options off; off.escaped = false;
        CHECK(!hasGroup(run(off, bytes(json)), "cdn.example.com"), "Escaped decoder off: JSON-escaped URL not found");

        std::vector<uint8_t> w; const std::string wj = "https:\\/\\/w.example.com\\/z";
        w.push_back(0); w.push_back(0);
        for (unsigned char c : wj) { w.push_back(c); w.push_back(0); }
        w.push_back(0); w.push_back(0);
        auto* fw = only(run(o, w), "https://w.example.com/z");
        CHECK(fw && fw->offset == 2, "JSON-escaped URL in UTF-16 found, exact offset");

        ur::Options mail; mail.mode = ur::Mode::Regex; mail.presets = {"email"};
        CHECK(only(run(mail, bytes("\x01to=user%40mail.example.com&x=1\x01")), "user@mail.example.com"),
              "percent-encoded email found in regex mode");
    }

    // match context never ends inside a UTF-8 character
    {
        ur::Options o; o.mode = ur::Mode::Regex; o.customRegex = "TOKEN";
        std::string s = "\x01";
        for (int i = 0; i < 20; ++i) s += "\xC3\xA4";   // 40 bytes of ä before the hit
        s += "TOKEN";
        for (int i = 0; i < 20; ++i) s += "\xC3\xB6";
        s += "\x01";
        auto g = run(o, std::vector<uint8_t>(s.begin(), s.end()));
        bool clean = !g.empty() && !g[0].items.empty();
        if (clean) {
            const auto& f = g[0].items[0];
            for (const std::string* c : {&f.before, &f.after})
                clean = clean && !c->empty() && (uint8_t((*c)[0]) & 0xC0) != 0x80 &&
                        (c->size() % 2) == 0;
        }
        CHECK(clean, "context cut at 32 bytes keeps whole UTF-8 characters");
    }

    std::printf(failures ? "\n%d FAILURE(S)\n" : "\nALL PASS\n", failures);
    return failures ? 1 : 0;
}
