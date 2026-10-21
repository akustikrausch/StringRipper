#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <tuple>
#include <vector>

namespace ur {

using PeSection = std::tuple<std::string, uint32_t, uint64_t>;

inline std::vector<PeSection> parsePeSections(const uint8_t* h, std::size_t n) {
    std::vector<PeSection> out;
    if (n < 0x40 || h[0] != 'M' || h[1] != 'Z') return out;
    uint32_t pe = 0;
    std::memcpy(&pe, h + 0x3C, 4);
    if (pe > n || n - pe < 64 || std::memcmp(h + pe, "PE\0\0", 4) != 0) return out;
    uint16_t count = 0, opt = 0;
    uint32_t align = 0;
    std::memcpy(&count, h + pe + 6, 2);
    std::memcpy(&opt, h + pe + 20, 2);
    std::memcpy(&align, h + pe + 56, 4);
    if (!align || (align & (align - 1))) align = 0x1000;
    const std::size_t start = std::size_t(pe) + 24;
    if (start > n || opt > n - start) return out;
    for (std::size_t s = start + opt, i = 0; i < count && s <= n && n - s >= 40; ++i, s += 40) {
        std::string name;
        for (std::size_t j = 0; j < 8 && h[s + j]; ++j)
            if (h[s + j] >= 0x20 && h[s + j] <= 0x7E) name += char(h[s + j]);
        uint32_t size = 0, va = 0;
        std::memcpy(&size, h + s + 8, 4);
        std::memcpy(&va, h + s + 12, 4);
        if (!size) std::memcpy(&size, h + s + 16, 4);
        const uint64_t end = (uint64_t(va) + size + align - 1) & ~(uint64_t(align) - 1);
        out.emplace_back(std::move(name), va, end);
    }
    return out;
}

} // namespace ur
