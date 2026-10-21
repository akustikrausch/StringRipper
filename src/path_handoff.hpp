#pragma once

#include <algorithm>
#include <cstddef>
#include <string>
#include <vector>

namespace ur {

inline std::vector<std::wstring> parsePathHandoff(const void* bytes, std::size_t size) {
    std::vector<std::wstring> paths;
    if (!bytes || size < 2 * sizeof(wchar_t) || size % sizeof(wchar_t)) return paths;
    const auto* text = static_cast<const wchar_t*>(bytes);
    const std::size_t count = size / sizeof(wchar_t);
    if (text[count - 1] || text[count - 2]) return paths;
    for (std::size_t pos = 0; pos + 1 < count;) {
        const auto* end = std::find(text + pos, text + count, L'\0');
        if (end == text + pos || end == text + count) return {};
        paths.emplace_back(text + pos, end);
        pos = std::size_t(end - text) + 1;
    }
    return paths;
}

} // namespace ur
