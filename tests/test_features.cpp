#include "../src/result_tools.hpp"
#include "../src/regex_presets.hpp"
#include <cstdio>

static int failures = 0;
#define CHECK(c) do { if (!(c)) { std::printf("FAIL line %d: %s\n", __LINE__, #c); ++failures; } } while (0)

int main() {
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
    CHECK(ur::csvField("a,\"b\"\r\n") == "\"a,\"\"b\"\"\r\n\"");
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
        CHECK(r[2].value == "https://g1.ikmultimedia.com/plugins/AmpliTube5/AmpliTube_5_10_9.zip");
        CHECK(r[2].captures.size() == 2 && r[2].captures[0].second == "/plugins/AmpliTube5/AmpliTube_5_10_9.zip" &&
              r[2].captures[1].second == "https://g1.ikmultimedia.com/plugins/AmpliTube5/AmpliTube_5_10_8.zip");
        CHECK(r[3].value == "https://g1.ikmultimedia.com/plugins/TONEX/TONEX_1_2.zip");
        CHECK(r[4].value == "https://g1.ikmultimedia.com/plugins/x.dmg");
        CHECK(r[5].value == "/nowhere/else.pkg" && r[5].captures.empty());       // no shared directory
        CHECK(r[6].value == "/plugins/AmpliTube5/other.zip");                    // other source
        CHECK(r[7].value == "setup.exe");                                        // no path at all
        CHECK(groups[1].items[2].value == "/d/3.zip");                           // two hosts tied
    }
    return failures ? 1 : 0;
}
