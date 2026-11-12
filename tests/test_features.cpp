#include "../src/result_tools.hpp"
#include "../src/regex_presets.hpp"
#include "../src/pe_sections.hpp"
#include "../src/path_handoff.hpp"
#include "../src/update_validation.hpp"
#include "../src/cli_args.hpp"
#include <cstdio>

static int failures = 0;
#define CHECK(c) do { if (!(c)) { std::printf("FAIL line %d: %s\n", __LINE__, #c); ++failures; } } while (0)

int main(int argc, char** argv) {
    CHECK(ur::cliNumber("010") == 10 && ur::cliNumber("0x10") == 16);
    if (argc > 1 && std::string(argv[1]) == "--invalid-json") {
        ur::Finding finding{};
        finding.value = "https://valid.example.com/x";
        finding.before = std::string("\xFC", 1);
        ur::Group group{"valid.example.com", {finding}};
        const auto json = ur::exportResults({group}, "json");
        std::fwrite(json.data(), 1, json.size(), stdout);
        return 0;
    }
    CHECK(ur::validUpdateVersion("1.2.7") && !ur::validUpdateVersion("99.0.0\\..\\x") &&
          !ur::validUpdateVersion("1..2") && !ur::validUpdateVersion("1\n2"));
    CHECK(ur::validUpdateNotes("https://example.com/notes") &&
          !ur::validUpdateNotes("file:///notes") && !ur::validUpdateNotes("https://example.com\nother"));
    CHECK(ur::settingLine("first\r\nsecond") == "first  second");
    {
        const wchar_t good[] = {L'o', L'n', L'e', 0, L't', L'w', L'o', 0, 0};
        auto paths = ur::parsePathHandoff(good, sizeof(good));
        CHECK(paths.size() == 2 && paths[0] == L"one" && paths[1] == L"two");
        CHECK(ur::parsePathHandoff(good, sizeof(wchar_t)).empty());
        CHECK(ur::parsePathHandoff(good, sizeof(good) - 1).empty());
        CHECK(ur::parsePathHandoff(good, sizeof(good) - sizeof(wchar_t)).empty());
    }
    {
        std::vector<uint8_t> h(4096);
        h[0] = 'M'; h[1] = 'Z';
        for (uint32_t pe : {0u, 0xF00u, 0xFFFFFFF0u}) {
            std::memcpy(h.data() + 0x3C, &pe, 4);
            CHECK(ur::parsePeSections(h.data(), h.size()).empty());
        }
        const uint32_t pe = 0xF00, va = 0x1000, size = 0x10, align = 0x1000;
        const uint16_t count = 1;
        std::memcpy(h.data() + 0x3C, &pe, 4);
        std::memcpy(h.data() + pe, "PE\0\0", 4);
        std::memcpy(h.data() + pe + 6, &count, 2);
        std::memcpy(h.data() + pe + 56, &align, 4);
        std::memcpy(h.data() + pe + 24, ".t\x01" "ext", 6);
        std::memcpy(h.data() + pe + 32, &size, 4);
        std::memcpy(h.data() + pe + 36, &va, 4);
        const auto sections = ur::parsePeSections(h.data(), h.size());
        CHECK(sections.size() == 1 && std::get<0>(sections[0]) == ".text" &&
              std::get<1>(sections[0]) == va && std::get<2>(sections[0]) == 0x2000);
    }
    ur::Group a{"Tickets", {{"TKT-123456", ur::Enc::Ascii, "before", "Tickets"}}};
    ur::Group b{"Tickets", {{"TKT-123456", ur::Enc::Utf16, "moved", "Tickets"},
                           {"TKT-654321", ur::Enc::Ascii, "after", "Tickets"}}};
    ur::ScanComparison comparison;
    CHECK(!comparison.matches("file"));
    comparison.remember("file", {a});
    CHECK(comparison.matches("file"));
    CHECK(!comparison.matches("other"));
    auto added = comparison.added({b});
    CHECK(ur::countFindings(added) == 1 && added[0].items[0].value == "TKT-654321");
    CHECK(comparison.added({a}).empty());
    comparison.remember("file", {b});
    CHECK(comparison.added({b}).empty());
    comparison.clear();
    CHECK(!comparison.matches("file"));
    ur::Options o;
    auto key = ur::comparisonContext("file", o);
    o.ascii = false;
    CHECK(key != ur::comparisonContext("file", o));
    CHECK(key != ur::comparisonContext("other", ur::Options{}));
    CHECK(ur::jsonString("\"\\\n\t") == "\"\\\"\\\\\\u000a\\u0009\"");
    CHECK(ur::jsonString(std::string("\xFC", 1)) == "\"\\u00fc\"");
    CHECK(ur::jsonString(std::string("\xC3\xBC", 2)) == std::string("\"\xC3\xBC\"", 4));
    CHECK(ur::csvField("a,\"b\"\r\n") == "\"a,\"\"b\"\"\r\n\"");
    CHECK(ur::csvField(std::string("a\0b", 3)) == "\"a\\0b\"");
    // Regression: csv cells starting with = + - @ or tab ran as formulas
    CHECK(ur::csvField("=cmd|'/c calc'!A1") == "\"'=cmd|'/c calc'!A1\"");
    CHECK(ur::csvField("+1-1") == "\"'+1-1\"");
    CHECK(ur::csvField("-1+1") == "\"'-1+1\"");
    CHECK(ur::csvField("@SUM(1,1)") == "\"'@SUM(1,1)\"");
    CHECK(ur::csvField("plain-value") == "\"plain-value\""); // unaffected: - not in first position
    CHECK(ur::exportResults({}, "json") == "[\n\n]\n");
    CHECK(ur::exportResults({}, "csv") ==
          "group,value,encoding,source,offset,context_before,context_after,captures\r\n");
    auto json = ur::exportResults({a}, "json");
    CHECK(json.find("\"group\":\"Tickets\"") != std::string::npos);
    CHECK(json.find("\"encoding\":\"ASCII\"") != std::string::npos);
    CHECK(json.find("\"source\":\"before\"") != std::string::npos);
    CHECK(json.find("\"offset\":null") != std::string::npos);
    {
        // the same value in one group shows once, counted; the first occurrence stays
        auto f = [](std::string v, std::string src, uint64_t off) { ur::Finding x{}; x.value = v; x.source = src; x.offset = off; x.hasOffset = true; return x; };
        ur::Group g{"host.tld", {f("https://host.tld/a", "app [stack]", 40), f("https://host.tld/b", "app [heap]", 20),
                                 f("https://host.tld/a", "app [private]", 30), f("https://host.tld/a", "app [heap]", 10)}};
        auto folded = ur::foldDuplicates({g});
        CHECK(folded.size() == 1 && folded[0].items.size() == 2);
        CHECK(folded[0].items[0].value == "https://host.tld/a" && folded[0].items[0].occurrences == 3);
        CHECK(folded[0].items[0].source == "app [heap]" && folded[0].items[0].offset == 10);   // first by source and offset, not by arrival
        CHECK(folded[0].items[1].occurrences == 1);
        CHECK(ur::foldDuplicates(folded)[0].items[0].occurrences == 3);                       // folding twice is stable
        CHECK(ur::exportResults({g}, "csv").find("occurrences") == std::string::npos);        // exports keep every hit, format unchanged
        CHECK(ur::plainList(folded) == "host.tld  (2)\r\n\r\nhttps://host.tld/a\r\nhttps://host.tld/b\r\n");   // editor/txt: once, no offset
    }
    auto stats = ur::summarizeResults({a, b});
    CHECK(stats.findings == 3 && stats.byGroup.at("Tickets") == 3);
    CHECK(stats.bySource.at("before") == 1 && stats.byEncoding.at("ASCII") == 2);
    bool threw = false;
    try { ur::exportResults({}, "xml"); } catch (const std::invalid_argument&) { threw = true; }
    CHECK(threw);
    ur::UserPreset preset;
    preset.name = "Tickets"; preset.pattern = "^TKT-[0-9]{6}$"; preset.utf16 = false;
    ur::Detector d(ur::presetOptions(preset));
    ur::Sink sink;
    d.testText("bad\r\nTKT-123456\r\nTKT-123456\nprefix TKT-654321", sink);
    CHECK(sink.items.size() == 1 && sink.items[0].value == "TKT-123456");
    CHECK(sink.items[0].group == "Tickets");
    preset.custom = false; preset.email = true;
    ur::Detector builtin(ur::presetOptions(preset));
    ur::Sink mail; builtin.testText("team@example.org", mail);
    CHECK(mail.items.size() == 1);
    auto args = ur::presetCli({"--regex", "--user-preset"}, "missing.ini");
    CHECK(args.presets.empty());
    threw = false;
    try { ur::presetCli({"--user-preset"}, "missing.ini"); }
    catch (const std::invalid_argument&) { threw = true; }
    CHECK(threw);
    {
        auto r = ur::IgnoreRules::parse({"  Microsoft.com ", "# note", "", "*TELEMETRY*", "=https://x.example.com/a"});
        CHECK(r.hidesGroup("login.microsoft.com") && r.hidesGroup("microsoft.com"));
        CHECK(!r.hidesGroup("notmicrosoft.com") && !r.hidesGroup("microsoft.com.evil.net"));
        CHECK(r.hidesValue("https://api.example.com/telemetry/v2"));
        CHECK(r.hidesValue("HTTPS://X.EXAMPLE.COM/A") && !r.hidesValue("https://x.example.com/ab"));
        CHECK(ur::IgnoreRules::parse({"# only a comment", " "}).empty());
        std::vector<ur::Group> g{{"login.microsoft.com", {{"https://login.microsoft.com/", ur::Enc::Ascii, "s", "login.microsoft.com"}}},
                                 {"cdn.example.com", {{"https://cdn.example.com/app.zip", ur::Enc::Ascii, "s", "cdn.example.com"},
                                                      {"https://cdn.example.com/telemetry", ur::Enc::Ascii, "s", "cdn.example.com"}}}};
        std::size_t hidden = 0;
        auto kept = ur::filterIgnored(g, r, &hidden);
        CHECK(hidden == 2 && kept.size() == 1 && kept[0].items.size() == 1 &&
              kept[0].items[0].value == "https://cdn.example.com/app.zip");
        ur::Options esc, plain; plain.escaped = false;
        CHECK(ur::comparisonContext("src", esc) != ur::comparisonContext("src", plain));
    }
    std::puts(failures ? "FAILED" : "ALL PASS");
    {
        // partial download paths borrow scheme+host from a full URL of the same source
        auto hit = [](std::string v, std::string src) { ur::Finding f{}; f.value = v; f.source = src; f.group = "Download URL"; return f; };
        ur::Group dl{"Download URL", {
            hit("https://g1.ikmultimedia.com/plugins/AmpliTube5/AmpliTube_5_10_8.zip", "pm.exe [heap]"),
            hit("https://cdn.other.com/misc/tool.exe", "pm.exe [heap]"),
            hit("/plugins/AmpliTube5/AmpliTube_5_10_9.zip", "pm.exe [xul.dll .rdata]"),
            hit("plugins/TONEX/TONEX_1_2.zip", "pm.exe [private]"),
            hit("g1.ikmultimedia.com/plugins/x.dmg", "pm.exe"),
            hit("/nowhere/else.pkg", "pm.exe"),
            hit("/plugins/AmpliTube5/other.zip", "other.exe"),
            hit("setup.exe", "pm.exe")}};
        ur::Group tie{"Download URL", {
            hit("https://a.com/d/1.zip", "t"), hit("https://b.com/d/2.zip", "t"), hit("/d/3.zip", "t")}};
        std::vector<ur::Group> groups{dl, tie};
        CHECK(ur::resolveDownloadHosts(groups) == 3);
        const auto& r = groups[0].items;
        auto find = [&](const std::string& value) -> const ur::Finding* {
            auto it = std::find_if(r.begin(), r.end(), [&](const ur::Finding& f) { return f.value == value; });
            return it == r.end() ? nullptr : &*it;
        };
        const auto* resolvedHit = find("https://g1.ikmultimedia.com/plugins/AmpliTube5/AmpliTube_5_10_9.zip");
        CHECK(resolvedHit && resolvedHit->captures.size() == 2 &&
              resolvedHit->captures[0].second == "/plugins/AmpliTube5/AmpliTube_5_10_9.zip" &&
              resolvedHit->captures[1].second == "https://g1.ikmultimedia.com/plugins/AmpliTube5/AmpliTube_5_10_8.zip");
        CHECK(find("https://g1.ikmultimedia.com/plugins/TONEX/TONEX_1_2.zip"));
        CHECK(find("https://g1.ikmultimedia.com/plugins/x.dmg"));
        const auto* unresolved = find("/nowhere/else.pkg");
        CHECK(unresolved && unresolved->captures.empty());
        CHECK(find("/plugins/AmpliTube5/other.zip"));
        CHECK(find("setup.exe"));
        CHECK(std::is_sorted(r.begin(), r.end(), [](const ur::Finding& a, const ur::Finding& b) {
            return a.value > b.value;
        }));
        CHECK(groups[1].items[2].value == "/d/3.zip");                           // two hosts tied
    }
    return failures ? 1 : 0;
}
