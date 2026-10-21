#pragma once

#include "path_encoding.hpp"
#include "regex_presets.hpp"
#include "workspace.hpp"
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <limits>
#include <stdexcept>

namespace ur {

struct CliArgs {
    Options options;
    PresetCli preset;
    std::vector<std::filesystem::path> inputs;
    std::filesystem::path outFile, dbFile = "stringripper-sessions.sqlite";
    FileSelection selection;
    std::string format = "txt", name, sessionName, jobName, runJob, favorite;
    std::vector<std::string> ignore;
    uint32_t pid = 0;
    int64_t openSession = 0, compareA = 0, compareB = 0;
    bool help = false, listJobs = false, listFavorites = false;
};

inline uint64_t cliNumber(const std::string& value) {
    const bool hex = value.size() > 2 && value[0] == '0' && (value[1] == 'x' || value[1] == 'X');
    const std::size_t start = hex ? 2 : 0;
    if (value.empty() || start == value.size()) throw std::invalid_argument("invalid number: " + value);
    for (std::size_t i = start; i < value.size(); ++i) {
        const unsigned char c = static_cast<unsigned char>(value[i]);
        if (hex ? !std::isxdigit(c) : !std::isdigit(c)) throw std::invalid_argument("invalid number: " + value);
    }
    try { return std::stoull(value, nullptr, hex ? 16 : 10); }
    catch (...) { throw std::invalid_argument("invalid number: " + value); }
}

inline std::vector<std::string> cliCsv(const std::string& value) {
    std::vector<std::string> out;
    std::size_t start = 0;
    while (start <= value.size()) {
        const auto end = value.find(',', start);
        const auto token = value.substr(start, end == std::string::npos ? end : end - start);
        if (token.empty()) throw std::invalid_argument("empty list item: " + value);
        out.push_back(token);
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return out;
}

inline CliArgs parseCliArgs(const std::vector<std::string>& args, PresetCli preset, bool windows) {
    CliArgs cli;
    cli.preset = std::move(preset);
    cli.options = cli.preset.options;
    cli.help = args.empty();
    bool custom = false, builtin = false;
    auto path = [](const std::string& text) {
        auto result = pathFromUtf8(text);
        if (!result) throw std::invalid_argument("invalid path: " + text);
        return *result;
    };
    auto signedNumber = [](const std::string& text) {
        const auto value = cliNumber(text);
        if (value > uint64_t(std::numeric_limits<int64_t>::max()))
            throw std::invalid_argument("invalid number: " + text);
        return static_cast<int64_t>(value);
    };
    for (std::size_t i = 0; i < args.size(); ++i) {
        const auto& a = args[i];
        auto next = [&]() -> std::string {
            if (++i >= args.size() || args[i].empty() || args[i].rfind("--", 0) == 0)
                throw std::invalid_argument("missing value for " + a);
            return args[i];
        };
        if (a == "--help" || a == "-h" || a == "/?") cli.help = true;
        else if (a == "--cli") {}
        else if (a == "--file" || a == "--folder") cli.inputs.push_back(path(next()));
        else if (a == "--pid") {
            if (!windows) throw std::invalid_argument("--pid is Windows-only");
            const auto text = next();
            const auto value = cliNumber(text);
            if (!value || value > UINT32_MAX) throw std::invalid_argument("invalid pid: " + text);
            cli.pid = uint32_t(value);
        }
        else if (a == "--name") {
            if (!windows) throw std::invalid_argument("--name is Windows-only");
            cli.name = next();
        }
        else if (a == "--regex") {
            custom = true; cli.options.mode = Mode::Regex; cli.options.customRegex = next();
            cli.options.customLabel = "Custom"; cli.options.presets.clear(); cli.options.extraPatterns.clear();
        }
        else if (a == "--preset") {
            builtin = true; cli.options.mode = Mode::Regex; cli.options.presets = cliCsv(next());
            cli.options.customRegex.clear(); cli.options.extraPatterns.clear();
        }
        else if (a == "--scheme") {
            cli.options.schemes = cliCsv(next());
            for (auto& scheme : cli.options.schemes) {
                std::transform(scheme.begin(), scheme.end(), scheme.begin(),
                               [](unsigned char c) { return char(std::tolower(c)); });
                if (!detail::schemeKnown(scheme)) throw std::invalid_argument("unknown scheme: " + scheme);
            }
        }
        else if (a == "--icase") cli.options.caseInsensitive = true;
        else if (a == "--no-crap") cli.options.dropCrap = false;
        else if (a == "--no-ascii") cli.options.ascii = false;
        else if (a == "--no-utf16") cli.options.utf16 = false;
        else if (a == "--no-base64") cli.options.base64 = false;
        else if (a == "--no-hex") cli.options.hex = false;
        else if (a == "--no-escaped") cli.options.escaped = false;
        else if (a == "--ignore") cli.ignore.push_back(next());
        else if (a == "--out") cli.outFile = path(next());
        else if (a == "--format") cli.format = next();
        else if (a == "--include") cli.selection.include = next();
        else if (a == "--exclude") cli.selection.exclude = next();
        else if (a == "--min-size") cli.selection.minSize = cliNumber(next());
        else if (a == "--max-size") cli.selection.maxSize = cliNumber(next());
        else if (a == "--modified-after") cli.selection.modifiedAfter = signedNumber(next());
        else if (a == "--modified-before") cli.selection.modifiedBefore = signedNumber(next());
        else if (a == "--range-start") cli.selection.rangeStart = cliNumber(next());
        else if (a == "--range-end") cli.selection.rangeEnd = cliNumber(next());
        else if (a == "--db") cli.dbFile = path(next());
        else if (a == "--save-session") cli.sessionName = next();
        else if (a == "--open-session") cli.openSession = signedNumber(next());
        else if (a == "--compare-sessions") { cli.compareA = signedNumber(next()); cli.compareB = signedNumber(next()); }
        else if (a == "--save-job") cli.jobName = next();
        else if (a == "--run-job") cli.runJob = next();
        else if (a == "--list-jobs") cli.listJobs = true;
        else if (a == "--favorite") cli.favorite = next();
        else if (a == "--favorites") cli.listFavorites = true;
        else if (a == "--user-preset" || a == "--presets-file") next();
        else if (a == "--list-user-presets") {}
        else if (!a.empty() && a[0] == '-') throw std::invalid_argument("unknown option: " + a);
        else cli.inputs.push_back(path(a));
    }
    if (custom && builtin) throw std::invalid_argument("--regex cannot be combined with --preset");
    for (const auto& id : cli.options.presets) {
        const auto& builtins = builtinPresets();
        if (std::none_of(builtins.begin(), builtins.end(), [&](const Preset& p) { return p.id == id; }))
            throw std::invalid_argument("unknown preset: " + id);
    }
    if (cli.format != "txt" && cli.format != "csv" && cli.format != "json" && cli.format != "sqlite")
        throw std::invalid_argument("format must be txt, csv, json or sqlite");
    if (!cli.help && !cli.preset.list) for (const auto& input : cli.inputs) {
        std::error_code ec;
        if (!std::filesystem::exists(input, ec) || ec)
            throw std::invalid_argument("input does not exist: " + pathUtf8(input));
    }
    return cli;
}

} // namespace ur
