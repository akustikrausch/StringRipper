#include "../src/regex_presets.hpp"
#include "../src/scan_core.hpp"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <chrono>

int main() {
    ur::UserPreset a;
    a.name = "Ticket codes";
    a.description = "Matches support ticket IDs\non two lines";
    a.pattern = R"( \bTKT-[0-9]{6}\b )";
    a.positiveExamples = " TKT-123456 \n TKT-654321 ";
    a.negativeExamples = "not a ticket\nTKT-12";
    a.validated = true; a.ascii = true; a.utf16 = false;
    a.custom = true; a.email = true; a.download = true;
    std::vector<ur::UserPreset> in{a};
    std::string err;
    auto out = ur::parseUserPresets(ur::serializeUserPresets(in), &err);
    if (!err.empty() || out.size() != 1) return 1;
    const auto& b = out[0];
    if (b.name != a.name || b.description != a.description || b.pattern != a.pattern ||
        b.positiveExamples != a.positiveExamples || b.negativeExamples != a.negativeExamples) return 2;
    if (!b.validated || !b.ascii || b.utf16 || !b.custom || !b.email || !b.download) return 3;
    auto report = ur::testPresetExamples(b);
    if (report.failed || report.passed != 4) return 16;
    ur::UserPreset second = a; second.name = "Other"; second.pattern = "Z[0-9]+";
    auto profile = ur::profileOptions({a, second});
    if (profile.extraPatterns.size() != 1 || profile.extraPatterns[0].first != "Other") return 17;
    try { ur::Detector d(profile); } catch (const ur::RegexError&) { return 18; }
    auto dir = std::filesystem::temp_directory_path() /
        ("stringripper-preset-test-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::create_directories(dir);
    auto file = dir / "regex-user-presets.ini";
    std::filesystem::remove(file); std::filesystem::remove(file.string() + ".bak");
    if (!ur::saveUserPresets(file, in, &err)) return 4;
    in[0].name = "Changed";
    if (!ur::saveUserPresets(file, in, &err)) return 5;
    std::vector<ur::UserPreset> backup;
    if (!ur::loadUserPresets(file.string() + ".bak", backup, &err)) return 6;
    if (backup.size() != 1 || backup[0].name != "Ticket codes") return 7;
    {
        std::ofstream f(file, std::ios::binary | std::ios::trunc);
        f << "damaged settings";
    }
    if (ur::loadUserPresets(file, backup)) return 11;
    if (!ur::saveUserPresets(file, in, &err)) return 12;
    if (!ur::loadUserPresets(file.string() + ".bak", backup) ||
        backup[0].name != "Ticket codes") return 13;
    for (const std::string text : {
            "[Regex User Preset: test]\nASCII=maybe\n",
            "[Regex User Preset: test]\nASCII=1\nASCII=0\n",
            "[Regex User Preset: test]\n[Regex User Preset: TEST]\n"}) {
        ur::parseUserPresets(text, &err);
        if (err.empty()) return 14;
    }
    auto bom = ur::parseUserPresets("\xEF\xBB\xBF" + ur::serializeUserPresets(in), &err);
    if (!err.empty() || bom.size() != 1 || bom[0].pattern != a.pattern) return 15;
    std::filesystem::remove_all(dir);
    std::vector<ur::UserPreset> starter;
    if (!ur::loadUserPresets(std::filesystem::path(SR_SOURCE_DIR) / "regex-user-presets.ini", starter, &err)) return 8;
    if (starter.size() < 2) return 9;
    for (const auto& p : starter) {
        ur::Options o; o.mode = ur::Mode::Regex; o.customRegex = p.pattern;
        try { ur::Detector d(o); } catch (const ur::RegexError&) { return 10; }
        auto sample = ur::testPresetExamples(p);
        if (sample.passed != 2 || sample.failed) return 19;
    }
    std::puts("ALL PASS");
    return 0;
}
