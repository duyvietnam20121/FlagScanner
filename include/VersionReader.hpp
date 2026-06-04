#pragma once
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <string>
#include <optional>
#include "ProcessHandle.hpp"
#include "PatternMatcher.hpp"
#include "Logger.hpp"

// ============================================================
//  VersionReader.hpp
//  Đọc ClientVersion string ("version-xxxxxxxxxxxxxxxx")
//  từ memory của Roblox process.
//
//  Roblox lưu version dưới dạng:
//    std::string ClientVersion = "version-ad5d3e2906444472";
//
//  Cách tìm: scan memory tìm pattern "version-" + 16 hex chars
// ============================================================

namespace FFlag {

class VersionReader {
public:
    // Prefix cố định của mọi Roblox version string
    static constexpr const char* VERSION_PREFIX = "version-";
    static constexpr size_t      VERSION_HEX_LEN = 16;  // hex chars sau prefix
    static constexpr size_t      VERSION_TOTAL   = 24;  // "version-" + 16

    // ── Đọc version từ process memory ────────────────────
    // Scan toàn bộ readable regions tìm "version-<16hex>"
    [[nodiscard]] static std::string
    read(const ProcessHandle& proc,
         uintptr_t            moduleBase,
         size_t               moduleSize)
    {
        LOG_DEBUG("Scanning for ClientVersion string...");

        // Build pattern: 'v','e','r','s','i','o','n','-' + 16 hex bytes
        // Không dùng wildcard vì format rất cụ thể
        CompiledPattern pat = buildVersionPattern();

        auto regions = proc.queryRegions(
            moduleBase, moduleSize,
            /*readOnly=*/true, /*exec=*/false);

        std::vector<uint8_t> chunk;
        for (const auto& region : regions) {
            chunk.resize(region.size);
            size_t got = proc.readMemory(region.base, chunk.data(), region.size);
            if (got < VERSION_TOTAL) continue;
            chunk.resize(got);

            auto matches = PatternMatcher::findAll(chunk.data(), chunk.size(), pat);
            for (size_t off : matches) {
                // Đọc toàn bộ version string (tới null terminator)
                auto str = readVersionAt(chunk.data() + off, chunk.size() - off);
                if (str) {
                    LOG_OK("ClientVersion = \"%s\"", str->c_str());
                    return *str;
                }
            }
        }

        LOG_WARN("ClientVersion not found in memory");
        return "version-unknown";
    }

    // ── Validate format version string ───────────────────
    [[nodiscard]] static bool isValidVersion(const std::string& v) {
        if (v.size() < VERSION_TOTAL) return false;
        if (v.rfind(VERSION_PREFIX, 0) != 0) return false;
        for (size_t i = 8; i < 24 && i < v.size(); ++i) {
            char c = v[i];
            bool hex = (c >= '0' && c <= '9') ||
                       (c >= 'a' && c <= 'f') ||
                       (c >= 'A' && c <= 'F');
            if (!hex) return false;
        }
        return true;
    }

private:
    // Build CompiledPattern cho "version-" (8 bytes cố định)
    static CompiledPattern buildVersionPattern() {
        std::vector<uint8_t> bytes;
        std::vector<bool>    mask;
        for (char c : std::string(VERSION_PREFIX)) {
            bytes.push_back(static_cast<uint8_t>(c));
            mask.push_back(true);
        }
        // 16 hex chars tiếp theo: chỉ cần match ký tự đầu '0'-'9'/'a'-'f'
        // Dùng wildcard để tránh hardcode, validate sau
        for (int i = 0; i < 16; ++i) {
            bytes.push_back(0x00);
            mask.push_back(false);  // wildcard
        }
        return PatternMatcher::fromBytes(bytes, mask, "ClientVersion");
    }

    // Đọc và validate version string tại offset trong buffer
    static std::optional<std::string>
    readVersionAt(const uint8_t* buf, size_t available) {
        if (available < VERSION_TOTAL) return std::nullopt;
        std::string result;
        result.reserve(VERSION_TOTAL + 4);
        for (size_t i = 0; i < available && i < VERSION_TOTAL + 8; ++i) {
            char c = static_cast<char>(buf[i]);
            if (c == '\0') break;
            // Chỉ chấp nhận ký tự hợp lệ
            bool ok = (c >= '0' && c <= '9') ||
                      (c >= 'a' && c <= 'z') ||
                      (c >= 'A' && c <= 'Z') ||
                      c == '-' || c == '_';
            if (!ok) break;
            result += c;
        }
        if (!isValidVersion(result)) return std::nullopt;
        return result;
    }
};

} // namespace FFlag