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
    {
        ur::Options o; o.base64 = o.hex = o.utf16 = false;
        ur::Detector det(o);
        for (char prefix : {'x', '7'}) {
            const std::string data = std::string(1, prefix) + "https://real-host.com/abc";
            ur::Sink sink;
            det.scan(reinterpret_cast<const uint8_t*>(data.data()), data.size(), "prefix", sink, 100, true);
            CHECK(sink.items.size() == 1 && sink.items[0].value == "https://real-host.com/abc" &&
                  sink.items[0].offset == 101, "known scheme suffix survives letter or digit prefix");
        }
    }
    {
        ur::Options o; o.base64 = o.hex = o.utf16 = o.escaped = false;
        ur::Detector det(o);
        const std::string url = "https://long.example.com/path";
        for (std::size_t count : {9000u, 100000u}) {
            std::string data(count, 'x');
            data += url;
            data += ' ';
            ur::Sink sink;
            det.scan(reinterpret_cast<const uint8_t*>(data.data()), data.size(), "long", sink, 100, true);
            CHECK(sink.items.size() == 1 && sink.items[0].value == url &&
                  sink.items[0].offset == 100 + count, "long run retains URL and exact offset");
        }
        std::string boundary(16380, 'x');
        boundary += url;
        boundary += ' ';
        ur::Sink sink;
        det.scan(reinterpret_cast<const uint8_t*>(boundary.data()), boundary.size(), "boundary", sink, 0, true);
        CHECK(sink.items.size() == 1 && sink.items[0].value == url &&
              sink.items[0].offset == 16380, "slice overlap retains boundary URL once");
    }

    // Regex mode: email + AWS key
    {
        ur::Options o; o.mode = ur::Mode::Regex; o.presets = {"email", "apikey"};
        auto g = run(o, buf);
        CHECK(hasValue(g, "telemetry@mail.example.com"), "regex email match");
        CHECK(hasValue(g, "AKIA1234567890ABCDEF"), "regex aws key match");
    }

    {
        ur::Options o; o.base64 = o.hex = o.utf16 = false;
        ur::Detector det(o); ur::Sink sink;
        const std::string tail = "https://example-cdn.co";
        det.scan(reinterpret_cast<const uint8_t*>(tail.data()), tail.size(), "tail", sink, 0, true, false, true);
        CHECK(sink.items.empty(), "cut tail does not emit shortened URL");
        det.scan(reinterpret_cast<const uint8_t*>(tail.data()), tail.size(), "whole", sink);
        CHECK(sink.items.size() == 1, "true end of data can emit URL");

        o.mode = ur::Mode::Regex; o.presets = {"email"};
        ur::Detector email(o); ur::Sink head;
        const std::string cut = "al@example.com";
        email.scan(reinterpret_cast<const uint8_t*>(cut.data()), cut.size(), "head", head, 0, true, true, false);
        CHECK(head.items.empty(), "cut head does not emit shortened email");
        email.scan(reinterpret_cast<const uint8_t*>(cut.data()), cut.size(), "whole", head);
        CHECK(head.items.size() == 1, "true start of data can emit email");

        o.mode = ur::Mode::Urls; o.ascii = false; o.hex = true;
        ur::Detector decoded(o); ur::Sink encoded;
        const std::string partial = hex("https://example-cdn.co");
        decoded.scan(reinterpret_cast<const uint8_t*>(partial.data()), partial.size(), "hex-tail",
                     encoded, 0, true, false, true);
        CHECK(encoded.items.empty(), "cut hex tail does not emit shortened URL");
        decoded.scan(reinterpret_cast<const uint8_t*>(partial.data()), partial.size(), "hex-whole", encoded);
        CHECK(encoded.items.size() == 1, "complete hex run can emit URL");
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
    {
        ur::Options o; o.mode = ur::Mode::Regex; o.customRegex = "[A-Z]{20}";
        std::string data(1200, 'A');
        ur::Detector det(o); ur::Sink sink;
        det.scan(reinterpret_cast<const uint8_t*>(data.data()), data.size(), "tokens", sink, 100, true);
        bool aligned = sink.items.size() == 60;
        for (std::size_t i = 0; i < sink.items.size(); ++i)
            aligned &= sink.items[i].offset == 100 + i * 20;
        CHECK(aligned, "regex windows keep 60 adjacent tokens aligned");
        o.customRegex = "A+"; ur::Detector longMatch(o); ur::Sink longSink;
        data.resize(600);
        longMatch.scan(reinterpret_cast<const uint8_t*>(data.data()), data.size(), "long", longSink);
        CHECK(longSink.items.empty(), "600-character match does not become a 512-character piece");
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

    // UTF-16 after a zero byte: one hit, at the LE offset, not a BE twin one byte earlier
    {
        std::vector<uint8_t> w; w.push_back(0); w.push_back(0);
        for (char c : std::string("https://cdn.example.com/plain/file.rar")) { w.push_back((uint8_t)c); w.push_back(0); }
        w.push_back(0); w.push_back(0);
        ur::Options url;
        auto g = run(url, w);
        CHECK(ur::countFindings(g) == 1 && g[0].items[0].offset == 2, "UTF-16 LE after a zero byte reported once, at its own offset");
        std::vector<uint8_t> odd; odd.push_back(7);
        for (char c : std::string("https://cdn.example.com/odd/file.rar")) { odd.push_back(0); odd.push_back((uint8_t)c); }
        odd.push_back(0); odd.push_back(0);
        auto gb = run(url, odd);
        CHECK(ur::countFindings(gb) == 1, "UTF-16 BE at an odd offset reported once");
    }
    // letters of other languages stay in a URL path; host stays ASCII
    {
        auto bytes = [](const std::string& s) { return std::vector<uint8_t>(s.begin(), s.end()); };
        const std::string want = "https://cdn.example.com/files/1.0.0/ufs/Pulsaci\xC3\xB3n.rar";
        ur::Options url;
        CHECK(hasValue(run(url, bytes("\x01" + want + "\x01")), want), "UTF-8 accented URL path kept whole");
        CHECK(hasValue(run(url, bytes("\x01https://cdn.example.com/files/1.0.0/ufs/Pulsaci\xF3n.rar\x01")), want),
              "ANSI accented URL path kept whole, as UTF-8");
        std::vector<uint8_t> w; w.push_back(0); w.push_back(0);
        for (unsigned char c : std::string("https://cdn.example.com/files/1.0.0/ufs/Pulsaci\xF3n.rar")) { w.push_back(c); w.push_back(0); }
        w.push_back(0); w.push_back(0);
        CHECK(hasValue(run(url, w), want), "UTF-16 accented URL path kept whole");
        const std::string cyr = "https://cdn.example.com/\xD1\x84\xD0\xB0\xD0\xB9\xD0\xBB/\xD0\xB4\xD0\xBE\xD0\xBA.pdf";
        CHECK(hasValue(run(url, bytes("\x01see " + cyr + " now\x01")), cyr), "Cyrillic UTF-8 path kept whole");
        const std::string quoted = "https://cdn.example.com/Gr\xC3\xB6\xC3\x9F" "e.zip";
        CHECK(hasValue(run(url, bytes("\x01\xE2\x80\x9C" + quoted + "\xE2\x80\x9D and more\x01")), quoted),
              "curly quote ends the URL");
        CHECK(!hasGroup(run(url, bytes("\x01https://b\xC3\xBC" "cher.example/x\x01")), "b\xC3\xBC" "cher.example"),
              "non-ASCII host is not reported");
        ur::Options dl; dl.mode = ur::Mode::Regex; dl.presets = {"fileurl"};
        CHECK(hasValue(run(dl, bytes("\x01/files/1.0.0/ufs/Pulsaci\xC3\xB3n.rar\x01")), "/files/1.0.0/ufs/Pulsaci\xC3\xB3n.rar"),
              "download preset keeps an accented file name");
        CHECK(hasValue(run(dl, bytes("\x01" + want + "\x01")), want), "download preset keeps an accented full URL");
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

        const std::string nested = "\x01https://outer.example.com/go?next=https%3A%2F%2Finner.example.org%2Fx\x01";
        auto nestedHits = run(o, bytes(nested));
        CHECK(only(nestedHits, "https://outer.example.com/go?next=https%3A%2F%2Finner.example.org%2Fx"),
              "outer URL with encoded redirect found once");
        auto* inner = only(nestedHits, "https://inner.example.org/x");
        CHECK(inner && inner->enc == ur::Enc::Escaped && inner->offset == nested.find("https%3A"),
              "nested encoded URL found with exact offset");

        ur::Options off; off.escaped = false;
        CHECK(!hasGroup(run(off, bytes(json)), "cdn.example.com"), "Escaped decoder off: JSON-escaped URL not found");

        std::vector<uint8_t> w; const std::string wj = "https:\\/\\/w.example.com\\/z";
        w.push_back(0); w.push_back(0);
        for (unsigned char c : wj) { w.push_back(c); w.push_back(0); }
        w.push_back(0); w.push_back(0);
        auto* fw = only(run(o, w), "https://w.example.com/z");
        CHECK(fw && fw->offset == 2, "JSON-escaped URL in UTF-16 found, exact offset");

        for (bool le : {true, false}) {
            std::vector<uint8_t> odd = {0, 0, 0xFF};
            const std::string url = "https://odd.example.com/path";
            for (unsigned char c : url) {
                odd.push_back(le ? c : 0);
                odd.push_back(le ? 0 : c);
            }
            odd.insert(odd.end(), {0xFF, 0xFF});
            auto oddHits = run(o, odd);
            auto* hit = only(oddHits, url);
            CHECK(hit && hit->enc == ur::Enc::Utf16 && hit->offset == 3,
                  le ? "odd-offset UTF-16 LE URL keeps byte offset" : "odd-offset UTF-16 BE URL keeps byte offset");
        }

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
