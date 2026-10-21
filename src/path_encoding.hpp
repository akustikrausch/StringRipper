#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

namespace ur {

inline std::string pathUtf8(const std::filesystem::path& path, bool generic = false) noexcept {
    try {
        const auto text = generic ? path.generic_u8string() : path.u8string();
        return {reinterpret_cast<const char*>(text.data()), text.size()};
    } catch (...) { return {}; }
}

inline std::optional<std::filesystem::path> pathFromUtf8(std::string_view text) noexcept {
    try { return std::filesystem::u8path(text); }
    catch (...) { return std::nullopt; }
}

} // namespace ur
