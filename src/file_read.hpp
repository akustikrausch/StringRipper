/* expand files and folders (recursive, no symlinks) into a flat file list */
#pragma once

#include <cstdint>
#include <filesystem>
#include <vector>

namespace ur {

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
