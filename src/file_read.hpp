// file_read.hpp - portable file and folder reading for StringRipper.
#pragma once

#include <cstdint>
#include <fstream>
#include <string>
#include <vector>
#include <filesystem>

namespace ur {

// Read a whole file into memory. Returns false on error.
inline bool readFile(const std::filesystem::path& p, std::vector<uint8_t>& out) {
    std::error_code ec;
    auto sz = std::filesystem::file_size(p, ec);
    if (ec) return false;
    std::ifstream f(p, std::ios::binary);
    if (!f) return false;
    out.resize(static_cast<std::size_t>(sz));
    if (sz) f.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(sz));
    return static_cast<bool>(f) || f.eof();
}

// Expand a list of inputs (files and/or folders) into a flat file list.
// Folders are walked recursively. Symlinks are not followed.
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

} // namespace ur
