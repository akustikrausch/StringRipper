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
    std::string out; int val = 0, bits = -6;
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

    // Merge across two sinks de-dups globally
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
        CHECK(ur::countFindings(g) == 1, "cross-sink duplicate collapsed to one");
    }

    // Bad custom regex -> throws
    {
        bool threw = false;
        try { ur::Options o; o.mode = ur::Mode::Regex; o.customRegex = "("; ur::Detector det(o); }
        catch (const ur::RegexError&) { threw = true; }
        CHECK(threw, "invalid custom regex rejected");
    }

    std::printf(failures ? "\n%d FAILURE(S)\n" : "\nALL PASS\n", failures);
    return failures ? 1 : 0;
}
