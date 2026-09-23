/* StringRipper CLI - portable core for macOS and Linux. Files and folders only;
   process memory is Windows-only (that reader is FXChainPlayer's, see main.cpp).
   URLs and regex out of files. build: build-macos.sh, or c++ -std=c++20. */
#include "scan_core.hpp"
#include "scan_driver.hpp"
#include "file_read.hpp"
#include "scan_service.hpp"
#include "version.h"
#include "regex_presets.hpp"
#include "result_tools.hpp"
#include "session_store.hpp"

#include <cstdio>
#include <cstdlib>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

static std::vector<std::string> splitCsv(const std::string& s) {
    std::vector<std::string> out; std::string cur;
    for (char c : s) { if (c == ',') { if (!cur.empty()) out.push_back(cur); cur.clear(); } else cur.push_back(c); }
    if (!cur.empty()) out.push_back(cur);
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
        "  --format TYPE    txt (default), csv, json or sqlite\n"
        "  --include GLOBS  include file patterns (comma-separated)\n"
        "  --exclude GLOBS  exclude file/folder patterns\n"
        "  --min-size N --max-size N  file size filter in bytes\n"
        "  --modified-after UNIX --modified-before UNIX  file date filter\n"
        "  --range-start N --range-end N  byte range (end exclusive)\n"
        "  --db FILE --save-session NAME  save the scan in a SQLite database\n"
        "  --open-session ID  display a previously saved session\n"
        "  --compare-sessions ID1 ID2  show added and removed results\n"
        "  --save-job NAME --run-job NAME --list-jobs  reusable scan jobs\n"
        "  --favorite PATH --favorites  mark or list favorite sources\n"
        "  --user-preset NAME       load a saved regex user preset\n"
        "  --list-user-presets      list saved preset names and exit\n"
        "  --presets-file PATH      INI location (default: next to executable)\n\n"
        "Process scanning (--pid) is Windows-only; use StringRipper.exe there.\n");
}

int main(int argc, char** argv) {
    ur::Options o;
    ur::PresetCli preset;
    try {
        preset = ur::presetCli(std::vector<std::string>(argv + 1, argv + argc), ur::executablePresets(argv[0]));
        o = preset.options;
    } catch (const std::exception& e) { std::fprintf(stderr, "error: %s\n", e.what()); return 2; }
    std::vector<std::filesystem::path> inputs;
    std::string outFile;
    std::string format = "txt";
    ur::FileSelection selection;
    std::string dbFile = "stringripper-sessions.sqlite", sessionName, jobName, runJob, favorite;
    bool listJobs = false, listFavorites = false;
    int64_t openSession = 0, compareA = 0, compareB = 0;
    bool help = argc < 2;

    auto number = [](const std::string& value) -> uint64_t {
        std::size_t used = 0;
        auto result = std::stoull(value, &used, 0);
        if (used != value.size()) throw std::invalid_argument("invalid number: " + value);
        return result;
    };

    try { for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&]() -> std::string { return (i + 1 < argc) ? argv[++i] : std::string(); };
        if (a == "--help" || a == "-h") help = true;
        else if (a == "--file" || a == "--folder") inputs.emplace_back(next());
        else if (a == "--regex") {
            o.mode = ur::Mode::Regex; o.customRegex = next(); o.customLabel = "Custom";
            o.presets.clear(); o.extraPatterns.clear();
        }
        else if (a == "--preset") {
            o.mode = ur::Mode::Regex; o.presets = splitCsv(next());
            o.customRegex.clear(); o.extraPatterns.clear();
        }
        else if (a == "--scheme") o.schemes = splitCsv(next());
        else if (a == "--icase") o.caseInsensitive = true;
        else if (a == "--no-crap") o.dropCrap = false;
        else if (a == "--no-ascii") o.ascii = false;
        else if (a == "--no-utf16") o.utf16 = false;
        else if (a == "--no-base64") o.base64 = false;
        else if (a == "--no-hex") o.hex = false;
        else if (a == "--out") outFile = next();
        else if (a == "--format") format = next();
        else if (a == "--include") selection.include = next();
        else if (a == "--exclude") selection.exclude = next();
        else if (a == "--min-size") selection.minSize = number(next());
        else if (a == "--max-size") selection.maxSize = number(next());
        else if (a == "--modified-after") selection.modifiedAfter = static_cast<int64_t>(number(next()));
        else if (a == "--modified-before") selection.modifiedBefore = static_cast<int64_t>(number(next()));
        else if (a == "--range-start") selection.rangeStart = number(next());
        else if (a == "--range-end") selection.rangeEnd = number(next());
        else if (a == "--db") dbFile = next();
        else if (a == "--save-session") sessionName = next();
        else if (a == "--open-session") openSession = static_cast<int64_t>(number(next()));
        else if (a == "--compare-sessions") { compareA = static_cast<int64_t>(number(next())); compareB = static_cast<int64_t>(number(next())); }
        else if (a == "--save-job") jobName = next();
        else if (a == "--run-job") runJob = next();
        else if (a == "--list-jobs") listJobs = true;
        else if (a == "--favorite") favorite = next();
        else if (a == "--favorites") listFavorites = true;
        else if (a == "--user-preset" || a == "--presets-file") next();
        else if (a == "--list-user-presets") {}
        else if (a == "--pid") { std::fprintf(stderr, "error: --pid is Windows-only\n"); return 2; }
        else if (!a.empty() && a[0] == '-') { std::fprintf(stderr, "error: unknown option %s\n", a.c_str()); return 2; }
        else inputs.emplace_back(a);
    } } catch (const std::exception& e) { std::fprintf(stderr, "error: %s\n", e.what()); return 2; }

    if (help) { usage(); return 0; }
    if (format != "txt" && format != "csv" && format != "json" && format != "sqlite") {
        std::fprintf(stderr, "error: format must be txt, csv, json or sqlite\n"); return 2;
    }
    if (preset.list) {
        for (const auto& p : preset.presets) std::printf("%s\n", p.name.c_str());
        return 0;
    }
    try {
        if (listJobs || listFavorites || !favorite.empty() || openSession || compareA || !runJob.empty()) {
            ur::SessionStore db(dbFile);
            if (listJobs) { for (const auto& n : db.listJobs()) std::puts(n.c_str()); return 0; }
            if (listFavorites) { for (const auto& n : db.favorites("source")) std::puts(n.c_str()); return 0; }
            if (!favorite.empty()) { db.setFavorite("source", favorite, true); return 0; }
            if (openSession) { std::fputs(ur::exportResults(db.loadSession(openSession).groups, format == "sqlite" ? "txt" : format).c_str(), stdout); return 0; }
            if (compareA) {
                auto delta = ur::compareSessions(db.loadSession(compareA).groups, db.loadSession(compareB).groups);
                std::printf("Added:\n%s\nRemoved:\n%s", ur::exportResults(delta.added, "txt").c_str(), ur::exportResults(delta.removed, "txt").c_str());
                return 0;
            }
            if (!runJob.empty()) {
                auto job = db.loadJob(runJob);
                if (!job) throw std::runtime_error("unknown job: " + runJob);
                o = job->options; selection = job->files; inputs = job->sources;
            }
        }
    } catch (const std::exception& e) { std::fprintf(stderr, "error: %s\n", e.what()); return 2; }
    if (inputs.empty()) { usage(); return 2; }

    if (!jobName.empty()) {
        try { ur::SessionStore db(dbFile); db.saveJob({jobName, inputs, 0, o, selection, 0}); }
        catch (const std::exception& e) { std::fprintf(stderr, "error: %s\n", e.what()); return 2; }
    }

    std::unique_ptr<ur::Detector> det;
    try { det = std::make_unique<ur::Detector>(o); }
    catch (const ur::RegexError& e) { std::fprintf(stderr, "error: %s\n", e.what()); return 2; }

    bool denied = false;
    auto groups = ur::scanPaths(*det, inputs, &denied, nullptr, {}, selection);
    if (denied) std::fprintf(stderr, "note: some sources could not be read\n");

    if (format == "sqlite" || !sessionName.empty()) {
        try {
            ur::SessionStore db(format == "sqlite" && !outFile.empty() ? outFile : dbFile);
            std::string source;
            for (const auto& p : inputs) { if (!source.empty()) source += "; "; source += p.string(); }
            auto id = db.saveSession({0, sessionName.empty() ? "Scan" : sessionName, source, "", groups});
            std::printf("saved %zu findings as session %lld\n", ur::countFindings(groups), static_cast<long long>(id));
        } catch (const std::exception& e) { std::fprintf(stderr, "error: %s\n", e.what()); return 2; }
        if (format == "sqlite") return 0;
    }

    std::string text = ur::exportResults(groups, format);
    if (!outFile.empty()) {
        std::FILE* fp = std::fopen(outFile.c_str(), "wb");
        if (!fp) { std::fprintf(stderr, "error: cannot write %s\n", outFile.c_str()); return 2; }
        auto written = std::fwrite(text.data(), 1, text.size(), fp);
        int closed = std::fclose(fp);
        if (written != text.size() || closed) { std::fprintf(stderr, "error: output write failed\n"); return 2; }
        std::printf("wrote %zu results to %s\n", ur::countFindings(groups), outFile.c_str());
    } else {
        std::fputs(text.c_str(), stdout);
    }
    return ur::countFindings(groups) ? 0 : 1;
}
