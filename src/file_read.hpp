/* expand files and folders (recursive, no symlinks) into a flat file list */
#pragma once

#include "workspace.hpp"
#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <string_view>
#include <vector>

namespace ur {

inline bool globMatch(std::string_view pattern, std::string_view value) {
    std::size_t p = 0, v = 0, star = std::string_view::npos, retry = 0;
    while (v < value.size()) {
        if (p < pattern.size() && (pattern[p] == '?' ||
            std::tolower(static_cast<unsigned char>(pattern[p])) ==
            std::tolower(static_cast<unsigned char>(value[v])))) { ++p; ++v; }
        else if (p < pattern.size() && pattern[p] == '*') { star = p++; retry = v; }
        else if (star != std::string_view::npos) { p = star + 1; v = ++retry; }
        else return false;
    }
    while (p < pattern.size() && pattern[p] == '*') ++p;
    return p == pattern.size();
}

inline bool patternListMatch(const std::string& patterns, const std::filesystem::path& path) {
    const auto filename = path.filename().string(), full = path.generic_string();
    std::size_t pos = 0;
    while (pos < patterns.size()) {
        auto end = patterns.find_first_of(";,", pos);
        auto token = patterns.substr(pos, end == std::string::npos ? end : end - pos);
        auto first = token.find_first_not_of(" \t");
        if (first != std::string::npos) {
            token.erase(0, first);
            token.erase(token.find_last_not_of(" \t") + 1);
            if (globMatch(token, filename) || globMatch(token, full)) return true;
            if (token.find('/') != std::string::npos) {
                for (std::size_t slash = full.find('/'); slash != std::string::npos;
                     slash = full.find('/', slash + 1))
                    if (globMatch(token, std::string_view(full).substr(slash + 1))) return true;
            }
        }
        if (end == std::string::npos) break;
        pos = end + 1;
    }
    return false;
}

inline bool selectedFile(const std::filesystem::path& path, const FileSelection& selection,
                         std::uintmax_t maxBytes = 0) {
    if (!selection.include.empty() && !patternListMatch(selection.include, path)) return false;
    if (!selection.exclude.empty() && patternListMatch(selection.exclude, path)) return false;
    std::error_code ec;
    const auto size = std::filesystem::file_size(path, ec);
    if (ec || (maxBytes && size > maxBytes) || size < selection.minSize ||
        (selection.maxSize && size > selection.maxSize)) return false;
    if (selection.modifiedAfter || selection.modifiedBefore) {
        auto modified = std::filesystem::last_write_time(path, ec);
        if (ec) return false;
        auto utc = std::chrono::time_point_cast<std::chrono::seconds>(
            modified - decltype(modified)::clock::now() + std::chrono::system_clock::now());
        auto seconds = utc.time_since_epoch().count();
        if ((selection.modifiedAfter && seconds < selection.modifiedAfter) ||
            (selection.modifiedBefore && seconds > selection.modifiedBefore)) return false;
    }
    return true;
}

inline std::vector<std::filesystem::path>
expandInputs(const std::vector<std::filesystem::path>& inputs, std::uintmax_t maxBytes = 0,
             const std::function<bool()>& cancel = {}, const FileSelection& selection = {}) {
    std::vector<std::filesystem::path> files;
    std::error_code ec;
    for (const auto& in : inputs) {
        if (cancel && cancel()) break;
        if (std::filesystem::is_directory(in, ec)) {
            for (auto it = std::filesystem::recursive_directory_iterator(
                     in, std::filesystem::directory_options::skip_permission_denied, ec);
                 it != std::filesystem::recursive_directory_iterator(); it.increment(ec)) {
                if (cancel && cancel()) return files;
                if (ec) break;
                if (it->is_directory(ec) && !selection.exclude.empty() &&
                    patternListMatch(selection.exclude, it->path())) { it.disable_recursion_pending(); continue; }
                if (!it->is_regular_file(ec) || !selectedFile(it->path(), selection, maxBytes)) continue;
                files.push_back(it->path());
            }
        } else if (std::filesystem::is_regular_file(in, ec)) {
            if (selectedFile(in, selection, maxBytes)) files.push_back(in);
        }
    }
    return files;
}

} // namespace ur
