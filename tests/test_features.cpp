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
    std::puts(failures ? "FAILED" : "ALL PASS");
    return failures ? 1 : 0;
}
