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
#include "cli_args.hpp"

#include <cstdio>
#include <cstdlib>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

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
        "  --no-ascii --no-utf16 --no-base64 --no-hex --no-escaped   turn off a decoder\n"
        "  --ignore RULE    hide a host (and its subdomains), a *glob* or =exact value; repeatable\n"
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
    ur::CliArgs cli;
    try {
        std::vector<std::string> args(argv + 1, argv + argc);
        cli = ur::parseCliArgs(args, ur::presetCli(args, ur::executablePresets(argv[0])), false);
    } catch (const std::exception& e) { std::fprintf(stderr, "error: %s\n", e.what()); return 2; }
    auto& o = cli.options;
    auto& inputs = cli.inputs;
    auto& selection = cli.selection;
    const auto outFile = ur::pathUtf8(cli.outFile), dbFile = ur::pathUtf8(cli.dbFile);
    const auto& format = cli.format;
    const auto& sessionName = cli.sessionName;
    const auto& jobName = cli.jobName;
    const auto& runJob = cli.runJob;
    const auto& favorite = cli.favorite;
    const auto& ignore = cli.ignore;
    if (cli.help) { usage(); return 0; }
    if (cli.preset.list) {
        for (const auto& p : cli.preset.presets) std::printf("%s\n", p.name.c_str());
        return 0;
    }
    try {
        if (cli.listJobs || cli.listFavorites || !favorite.empty() || cli.openSession || cli.compareA || !runJob.empty()) {
            ur::SessionStore db(dbFile);
            if (cli.listJobs) { for (const auto& n : db.listJobs()) std::puts(n.c_str()); return 0; }
            if (cli.listFavorites) { for (const auto& n : db.favorites("source")) std::puts(n.c_str()); return 0; }
            if (!favorite.empty()) { db.setFavorite("source", favorite, true); return 0; }
            if (cli.openSession) {
                auto text = ur::exportResults(db.loadSession(cli.openSession).groups, format == "sqlite" ? "txt" : format);
                std::fwrite(text.data(), 1, text.size(), stdout);
                return 0;
            }
            if (cli.compareA) {
                auto delta = ur::compareSessions(db.loadSession(cli.compareA).groups, db.loadSession(cli.compareB).groups);
                auto added = ur::exportResults(delta.added, "txt"), removed = ur::exportResults(delta.removed, "txt");
                std::fputs("Added:\n", stdout);
                std::fwrite(added.data(), 1, added.size(), stdout);
                std::fputs("\nRemoved:\n", stdout);
                std::fwrite(removed.data(), 1, removed.size(), stdout);
                return 0;
            }
            if (!runJob.empty()) {
                auto job = db.loadJob(runJob);
                if (!job) throw std::runtime_error("unknown job: " + runJob);
                if (job->sources.empty()) throw std::runtime_error("process jobs are Windows-only");
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
    ur::resolveDownloadHosts(groups);
    if (!ignore.empty()) groups = ur::filterIgnored(groups, ur::IgnoreRules::parse(ignore));
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
        std::fwrite(text.data(), 1, text.size(), stdout);
    }
    return ur::countFindings(groups) ? 0 : 1;
}
