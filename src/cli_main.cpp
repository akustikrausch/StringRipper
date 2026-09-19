/* StringRipper CLI - portable core for macOS and Linux. Files and folders only;
   process memory is Windows-only (that reader is FXChainPlayer's, see main.cpp).
   URLs and regex out of files. build: build-macos.sh, or c++ -std=c++20. */
#include "scan_core.hpp"
#include "scan_driver.hpp"
#include "file_read.hpp"
#include "version.h"

#include <cstdio>
#include <string>
#include <vector>

static std::vector<std::string> splitCsv(const std::string& s) {
    std::vector<std::string> out; std::string cur;
    for (char c : s) { if (c == ',') { if (!cur.empty()) out.push_back(cur); cur.clear(); } else cur.push_back(c); }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

static std::string resultsToText(const std::vector<ur::Group>& groups) {
    std::string out;
    for (const auto& g : groups) {
        if (!out.empty()) out += "\n";
        out += g.name + "  (" + std::to_string(g.items.size()) + ")\n\n";
        for (const auto& f : g.items) out += f.value + "\n";
    }
    return out;
}

static void usage() {
    std::printf(
        "StringRipper " SR_VER_STR " CLI (macOS/Linux) - URLs or regex out of files.\n\n"
        "Usage:\n"
        "  stringripper PATH ...              scan files or folders (folders recurse)\n"
        "  stringripper --file PATH ...\n"
        "  stringripper --folder PATH ...\n\n"
        "Options:\n"
        "  --regex PAT      regex mode with a custom ECMAScript pattern\n"
        "  --preset IDS     regex presets: email,ipv4,ipv6,guid,apikey,filepath,fileurl\n"
        "  --scheme LIST    URL mode: only these schemes (e.g. http,https)\n"
        "  --icase          case-insensitive matching\n"
        "  --no-crap        URL mode: keep placeholder/namespace hosts too\n"
        "  --no-ascii --no-utf16 --no-base64 --no-hex   turn off a decoder\n"
        "  --out FILE       write results to FILE\n\n"
        "Process scanning (--pid) is Windows-only; use StringRipper.exe there.\n");
}

int main(int argc, char** argv) {
    ur::Options o;
    std::vector<std::filesystem::path> inputs;
    std::string outFile;
    bool help = argc < 2;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&]() -> std::string { return (i + 1 < argc) ? argv[++i] : std::string(); };
        if (a == "--help" || a == "-h") help = true;
        else if (a == "--file" || a == "--folder") inputs.emplace_back(next());
        else if (a == "--regex") { o.mode = ur::Mode::Regex; o.customRegex = next(); }
        else if (a == "--preset") { o.mode = ur::Mode::Regex; o.presets = splitCsv(next()); }
        else if (a == "--scheme") o.schemes = splitCsv(next());
        else if (a == "--icase") o.caseInsensitive = true;
        else if (a == "--no-crap") o.dropCrap = false;
        else if (a == "--no-ascii") o.ascii = false;
        else if (a == "--no-utf16") o.utf16 = false;
        else if (a == "--no-base64") o.base64 = false;
        else if (a == "--no-hex") o.hex = false;
        else if (a == "--out") outFile = next();
        else if (a == "--pid") { std::fprintf(stderr, "error: --pid is Windows-only\n"); return 2; }
        else if (!a.empty() && a[0] == '-') { std::fprintf(stderr, "error: unknown option %s\n", a.c_str()); return 2; }
        else inputs.emplace_back(a);
    }

    if (help || inputs.empty()) { usage(); return help ? 0 : 2; }

    std::unique_ptr<ur::Detector> det;
    try { det = std::make_unique<ur::Detector>(o); }
    catch (const ur::RegexError& e) { std::fprintf(stderr, "error: %s\n", e.what()); return 2; }

    ur::ScanPool pool(*det, 0, 256u * 1024 * 1024);
    ur::DriverLimits lim;
    for (const auto& f : ur::expandInputs(inputs)) ur::scanFileInto(f, pool, lim);
    auto groups = pool.finish();

    std::string text = resultsToText(groups);
    if (!outFile.empty()) {
        std::FILE* fp = std::fopen(outFile.c_str(), "wb");
        if (!fp) { std::fprintf(stderr, "error: cannot write %s\n", outFile.c_str()); return 2; }
        std::fwrite(text.data(), 1, text.size(), fp);
        std::fclose(fp);
        std::printf("wrote %zu results to %s\n", ur::countFindings(groups), outFile.c_str());
    } else {
        std::fputs(text.c_str(), stdout);
    }
    return ur::countFindings(groups) ? 0 : 1;
}
