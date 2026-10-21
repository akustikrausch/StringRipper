#pragma once

#include <cctype>
#include <string>

namespace ur {

inline bool validUpdateVersion(const std::string& value) {
    if (value.empty() || value.front() == '.' || value.back() == '.') return false;
    bool dot = false;
    for (unsigned char c : value) {
        if (c == '.') { if (dot) return false; dot = true; }
        else if (c >= '0' && c <= '9') dot = false;
        else return false;
    }
    return true;
}

inline bool validUpdateNotes(const std::string& value) {
    if (value.rfind("https://", 0) != 0 || value.size() <= 8) return false;
    const auto hostEnd = value.find_first_of("/?#", 8);
    if (hostEnd == 8) return false;
    for (unsigned char c : value) if (c <= 0x20 || c == 0x7F) return false;
    return true;
}

inline std::string settingLine(std::string value) {
    for (char& c : value) if (c == '\r' || c == '\n') c = ' ';
    return value;
}

} // namespace ur
