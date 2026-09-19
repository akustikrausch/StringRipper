/* expand files and folders (recursive, no symlinks) into a flat file list */
#pragma once

#include <cstdint>
#include <filesystem>
#include <vector>

#ifndef _WIN32
#include <dirent.h>
#include <sys/stat.h>
#endif

namespace ur {

#ifdef _WIN32

inline std::vector<std::filesystem::path>
expandInputs(const std::vector<std::filesystem::path>& inputs, std::uintmax_t maxBytes = 0) {
    std::vector<std::filesystem::path> files;
    std::error_code ec;
    for (const auto& in : inputs) {
        if (std::filesystem::is_directory(in, ec)) {
            for (auto it = std::filesystem::recursive_directory_iterator(
                     in, std::filesystem::directory_options::skip_permission_denied, ec);
                 it != std::filesystem::recursive_directory_iterator(); it.increment(ec)) {
                if (ec) break;
                if (!it->is_regular_file(ec)) continue;
                if (maxBytes) {
                    auto s = it->file_size(ec);
                    if (!ec && s > maxBytes) continue;
                }
                files.push_back(it->path());
            }
        } else if (std::filesystem::is_regular_file(in, ec)) {
            files.push_back(in);
        }
    }
    return files;
}

#else
// POSIX (macOS / Linux): hand-rolled walk instead of
// std::filesystem::recursive_directory_iterator. Apple's libc++ marks that
// class (and its increment/comparison operators) unavailable before macOS
// 10.15 - fine for the arm64 slice (min 11.0) but a hard compile error for
// the x86_64 slice (min 10.13, see docs/MACOS.md). is_directory/is_regular_file
// are unaffected (plain stat calls), so only the traversal itself moves to
// opendir/readdir/lstat, which has no such version gate and behaves the same
// on Linux. Semantics preserved from the original filesystem-based version:
// directories are never entered through a symlink (no infinite loops), but a
// symlink that resolves to a regular file is still picked up, and a
// permission-denied subtree is skipped rather than aborting the whole scan.

namespace detail {

inline void walkDir(const std::filesystem::path& dir, std::uintmax_t maxBytes,
                     std::vector<std::filesystem::path>& files) {
    DIR* d = ::opendir(dir.c_str());
    if (!d) return; // permission denied / vanished: skip this subtree

    while (struct dirent* entry = ::readdir(d)) {
        const std::string name = entry->d_name;
        if (name == "." || name == "..") continue;

        std::filesystem::path path = dir / name;
        struct stat lst{};
        if (::lstat(path.c_str(), &lst) != 0) continue; // vanished/unreadable: skip

        if (S_ISLNK(lst.st_mode)) {
            // never recurse through a symlink; but if it resolves to a
            // regular file, include it (matches is_regular_file(), which
            // follows symlinks)
            struct stat tgt{};
            if (::stat(path.c_str(), &tgt) == 0 && S_ISREG(tgt.st_mode)) {
                if (!maxBytes || static_cast<std::uintmax_t>(tgt.st_size) <= maxBytes) {
                    files.push_back(std::move(path));
                }
            }
            continue;
        }

        if (S_ISDIR(lst.st_mode)) {
            walkDir(path, maxBytes, files);
        } else if (S_ISREG(lst.st_mode)) {
            if (maxBytes && static_cast<std::uintmax_t>(lst.st_size) > maxBytes) continue;
            files.push_back(std::move(path));
        }
    }
    ::closedir(d);
}

} // namespace detail

inline std::vector<std::filesystem::path>
expandInputs(const std::vector<std::filesystem::path>& inputs, std::uintmax_t maxBytes = 0) {
    std::vector<std::filesystem::path> files;
    std::error_code ec;
    for (const auto& in : inputs) {
        if (std::filesystem::is_directory(in, ec)) {
            detail::walkDir(in, maxBytes, files);
        } else if (std::filesystem::is_regular_file(in, ec)) {
            files.push_back(in);
        }
    }
    return files;
}

#endif

} // namespace ur
