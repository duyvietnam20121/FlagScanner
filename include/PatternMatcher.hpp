#pragma once
#include <vector>
#include <string>
#include <string_view>
#include <cstdint>
#include <algorithm>
#include <array>
#include "FlagTypes.hpp"
#include "Logger.hpp"

// ============================================================
//  FFlag Scanner/Dumper — PatternMatcher
//  File: PatternMatcher.hpp
//  Boyer-Moore-Horspool với wildcard (0xFF mask)
//  + IDA-style pattern parser ("AA BB ?? CC")
// ============================================================

namespace FFlag {

// ────────────────────────────────────────────────────────────
//  Struct: CompiledPattern — pattern đã compile sẵn bad-char
// ────────────────────────────────────────────────────────────
struct CompiledPattern {
    std::string          name;
    std::vector<uint8_t> bytes;
    std::vector<bool>    mask;      // true = phải match byte đó
    int                  nameOffset  = 0;
    int                  valueOffset = 0;

    // Bad-character table cho Boyer-Moore-Horspool
    std::array<int, 256> badChar{};

    [[nodiscard]] size_t length() const noexcept { return bytes.size(); }
    [[nodiscard]] bool   valid()  const noexcept { return !bytes.empty(); }
};

// ────────────────────────────────────────────────────────────
//  Class: PatternMatcher
// ────────────────────────────────────────────────────────────
class PatternMatcher {
public:
    // ── Parse IDA-style pattern string ───────────────────
    // Ví dụ: "48 89 5C 24 ?? 48 83 EC 20" (? hoặc ?? = wildcard)
    [[nodiscard]] static CompiledPattern parseIDA(
        const std::string& patStr,
        const std::string& name       = "",
        int                nameOffset = 0,
        int                valueOffset= 0)
    {
        CompiledPattern cp;
        cp.name        = name;
        cp.nameOffset  = nameOffset;
        cp.valueOffset = valueOffset;

        std::istringstream ss(patStr);
        std::string token;
        while (ss >> token) {
            if (token == "?" || token == "??") {
                cp.bytes.push_back(0x00);
                cp.mask.push_back(false);  // wildcard
            } else {
                uint8_t b = static_cast<uint8_t>(std::stoul(token, nullptr, 16));
                cp.bytes.push_back(b);
                cp.mask.push_back(true);
            }
        }

        buildBadChar(cp);
        LOG_DEBUG("Parsed pattern '%s': %zu bytes", name.c_str(), cp.bytes.size());
        return cp;
    }

    // ── Tạo pattern từ raw bytes + mask ──────────────────
    [[nodiscard]] static CompiledPattern fromBytes(
        const std::vector<uint8_t>& bytes,
        const std::vector<bool>&    mask,
        const std::string&          name       = "",
        int                         nameOffset = 0,
        int                         valueOffset= 0)
    {
        CompiledPattern cp;
        cp.name        = name;
        cp.bytes       = bytes;
        cp.mask        = mask;
        cp.nameOffset  = nameOffset;
        cp.valueOffset = valueOffset;
        buildBadChar(cp);
        return cp;
    }

    // ── Tìm tất cả lần xuất hiện pattern trong buffer ────
    // Trả về vector offset trong buffer
    [[nodiscard]] static std::vector<size_t>
    findAll(const uint8_t*          haystack,
            size_t                  haystackLen,
            const CompiledPattern&  pattern)
    {
        std::vector<size_t> results;
        const size_t patLen = pattern.length();

        if (patLen == 0 || haystackLen < patLen) return results;

        size_t i = 0;
        while (i <= haystackLen - patLen) {
            // So sánh từ cuối → đầu (Boyer-Moore style)
            int j = static_cast<int>(patLen) - 1;
            while (j >= 0 && (!pattern.mask[j] ||
                               haystack[i + j] == pattern.bytes[j]))
            {
                --j;
            }

            if (j < 0) {
                // Match thành công
                results.push_back(i);
                i += 1;  // tiếp tục tìm match kế
            } else {
                // Skip dùng bad-char table (chỉ cho byte thực, không wildcard)
                uint8_t  badByte  = haystack[i + patLen - 1];
                int      skip     = pattern.badChar[badByte];
                i += static_cast<size_t>(std::max(1, skip));
            }
        }

        return results;
    }

    // ── Tìm một lần xuất hiện đầu tiên ───────────────────
    [[nodiscard]] static std::optional<size_t>
    findFirst(const uint8_t*         haystack,
              size_t                 haystackLen,
              const CompiledPattern& pattern)
    {
        auto all = findAll(haystack, haystackLen, pattern);
        if (all.empty()) return std::nullopt;
        return all[0];
    }

    // ── String search: tìm tất cả prefix FFlag trong buffer ──
    // Nhanh hơn regex, tối ưu cho scan thô
    [[nodiscard]] static std::vector<size_t>
    findFlagNames(const uint8_t*                  haystack,
                  size_t                          haystackLen,
                  const std::vector<std::string>& prefixes,
                  size_t                          minLen = 5,
                  size_t                          maxLen = 256)
    {
        std::vector<size_t> results;
        if (haystackLen == 0) return results;

        // Lấy ký tự đầu của tất cả prefix (để quick reject)
        std::array<bool, 256> firstChars{};
        for (const auto& p : prefixes)
            if (!p.empty())
                firstChars[static_cast<uint8_t>(p[0])] = true;

        size_t i = 0;
        while (i < haystackLen) {
            uint8_t c = haystack[i];

            // Quick reject: ký tự đầu không khớp bất kỳ prefix nào
            if (!firstChars[c]) { ++i; continue; }

            // Thử match từng prefix
            bool matched = false;
            for (const auto& prefix : prefixes) {
                if (prefix.empty()) continue;
                size_t plen = prefix.size();
                if (i + plen > haystackLen) continue;

                if (memcmp(haystack + i, prefix.data(), plen) == 0) {
                    // Kiểm tra ký tự sau prefix phải là chữ hoa (A-Z)
                    if (i + plen < haystackLen) {
                        char nextCh = static_cast<char>(haystack[i + plen]);
                        if (nextCh >= 'A' && nextCh <= 'Z') {
                            // Đo độ dài tên flag (ASCII printable, không có space)
                            size_t nameLen = plen;
                            while (i + nameLen < haystackLen && nameLen < maxLen) {
                                char nc = static_cast<char>(haystack[i + nameLen]);
                                if (nc == '\0') break;
                                if (!isValidNameChar(nc)) break;
                                ++nameLen;
                            }
                            // Phải kết thúc bằng null và đủ dài
                            if (nameLen >= minLen &&
                                i + nameLen < haystackLen &&
                                haystack[i + nameLen] == '\0')
                            {
                                results.push_back(i);
                                matched = true;
                                i += nameLen + 1;  // skip qua chuỗi đã tìm thấy
                                break;
                            }
                        }
                    }
                }
            }
            if (!matched) ++i;
        }

        return results;
    }

    // ── Built-in Roblox FFlag patterns (x64) ─────────────
    // Các signature phổ biến trong RobloxPlayerBeta.exe
    [[nodiscard]] static std::vector<CompiledPattern> robloxPatterns() {
        std::vector<CompiledPattern> pats;

        // Pattern 1: FFlag bool setter
        // 48 8B 05 ?? ?? ?? ?? 84 C0 75 ?? B0 01
        pats.push_back(parseIDA(
            "48 8B 05 ?? ?? ?? ?? 84 C0 75 ?? B0 01",
            "FFlag_BoolSetter", -0x20, 0x03));

        // Pattern 2: FFlag string table ref
        // 4C 8D 05 ?? ?? ?? ?? 48 8D 15
        pats.push_back(parseIDA(
            "4C 8D 05 ?? ?? ?? ?? 48 8D 15",
            "FFlag_StringTableRef", 0x00, 0x03));

        // Pattern 3: FInt getter
        // 48 8B 0D ?? ?? ?? ?? 8B 41 ?? C3
        pats.push_back(parseIDA(
            "48 8B 0D ?? ?? ?? ?? 8B 41 ??",
            "FInt_Getter", 0x00, 0x03));

        return pats;
    }

private:
    // ── Build bad-character shift table (BMH) ────────────
    static void buildBadChar(CompiledPattern& cp) {
        const int patLen = static_cast<int>(cp.length());
        // Default: shift = patLen
        cp.badChar.fill(patLen);
        // Điền shift cho từng byte có mask (không phải wildcard)
        for (int i = 0; i < patLen - 1; ++i) {
            if (cp.mask[i]) {
                cp.badChar[cp.bytes[i]] = patLen - 1 - i;
            }
        }
    }

    // ── Ký tự hợp lệ trong tên FFlag ─────────────────────
    static bool isValidNameChar(char c) noexcept {
        return (c >= 'A' && c <= 'Z') ||
               (c >= 'a' && c <= 'z') ||
               (c >= '0' && c <= '9') ||
               c == '_';
    }
};

} // namespace FFlag

// Cần include sstream cho parseIDA
#include <sstream>
