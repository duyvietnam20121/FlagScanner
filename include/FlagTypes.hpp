#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <variant>
#include <cstdint>
#include <chrono>

// ============================================================
//  FFlag Scanner/Dumper — Roblox FFlag Research Tool
//  File: FlagTypes.hpp
//  Định nghĩa tất cả kiểu dữ liệu cốt lõi, enum, struct
// ============================================================

namespace FFlag {

// ────────────────────────────────────────────────────────────
//  Enum: FlagKind — phân loại flag chặt chẽ bằng enum class
// ────────────────────────────────────────────────────────────
enum class FlagKind : uint8_t {
    Unknown = 0,
    FFlag,      // bool
    FInt,       // int32
    FString,    // std::string
    FLog,       // log level int
    DFFlag,     // dynamic bool
    DFInt,      // dynamic int
    DFString,   // dynamic string
    SFFlag,     // sync bool
    SFInt,      // sync int
};

// Chuyển FlagKind → chuỗi tên prefix
inline const char* kindToPrefix(FlagKind k) noexcept {
    switch (k) {
        case FlagKind::FFlag:   return "FFlag";
        case FlagKind::FInt:    return "FInt";
        case FlagKind::FString: return "FString";
        case FlagKind::FLog:    return "FLog";
        case FlagKind::DFFlag:  return "DFFlag";
        case FlagKind::DFInt:   return "DFInt";
        case FlagKind::DFString:return "DFString";
        case FlagKind::SFFlag:  return "SFFlag";
        case FlagKind::SFInt:   return "SFInt";
        default:                return "Unknown";
    }
}

// Parse prefix string → FlagKind
inline FlagKind prefixToKind(const std::string& prefix) noexcept {
    static const std::unordered_map<std::string, FlagKind> table {
        {"FFlag",    FlagKind::FFlag},
        {"FInt",     FlagKind::FInt},
        {"FString",  FlagKind::FString},
        {"FLog",     FlagKind::FLog},
        {"DFFlag",   FlagKind::DFFlag},
        {"DFInt",    FlagKind::DFInt},
        {"DFString", FlagKind::DFString},
        {"SFFlag",   FlagKind::SFFlag},
        {"SFInt",    FlagKind::SFInt},
    };
    auto it = table.find(prefix);
    return (it != table.end()) ? it->second : FlagKind::Unknown;
}

// ────────────────────────────────────────────────────────────
//  Struct: FlagEntry — kết quả một FFlag tìm được
// ────────────────────────────────────────────────────────────
struct FlagEntry {
    std::string name;        // Tên flag ("FFlagMyFeature")
    FlagKind    kind;        // Loại flag (type-safe)
    std::string value;       // Giá trị stringify
    uintptr_t   address;     // Địa chỉ tuyệt đối trong process
    uintptr_t   rva;         // Relative Virtual Address (address - moduleBase)
    uintptr_t   namePtr;     // Con trỏ tới chuỗi tên trong memory
    uintptr_t   valuePtr;    // Con trỏ tới vùng giá trị trong memory

    // Helper: lấy prefix string từ kind
    [[nodiscard]] const char* typeName() const noexcept {
        return kindToPrefix(kind);
    }
    // Helper: phân loại bool flag
    [[nodiscard]] bool isBool()   const noexcept {
        return kind == FlagKind::FFlag  || kind == FlagKind::DFFlag || kind == FlagKind::SFFlag;
    }
    [[nodiscard]] bool isInt()    const noexcept {
        return kind == FlagKind::FInt   || kind == FlagKind::DFInt  || kind == FlagKind::SFInt;
    }
    [[nodiscard]] bool isString() const noexcept {
        return kind == FlagKind::FString || kind == FlagKind::DFString;
    }
    [[nodiscard]] bool isDynamic() const noexcept {
        return kind == FlagKind::DFFlag || kind == FlagKind::DFInt || kind == FlagKind::DFString;
    }
};

// ────────────────────────────────────────────────────────────
//  Struct: PatternEntry — một signature để scan
// ────────────────────────────────────────────────────────────
struct PatternEntry {
    std::string  name;       // Tên pattern (để log)
    std::vector<uint8_t> bytes;   // Bytes pattern (0xFF = wildcard)
    std::vector<bool>    mask;    // true = match byte, false = wildcard
    int          nameOffset;      // Offset từ match → tên flag (relative)
    int          valueOffset;     // Offset từ match → value ptr
};

// ────────────────────────────────────────────────────────────
//  Struct: ModuleInfo — thông tin một module (exe/dll)
// ────────────────────────────────────────────────────────────
struct ModuleInfo {
    uintptr_t   base  = 0;
    size_t      size  = 0;
    std::string name;
    std::string path;

    [[nodiscard]] bool valid() const noexcept { return base != 0 && size != 0; }
    [[nodiscard]] bool contains(uintptr_t addr) const noexcept {
        return addr >= base && addr < base + size;
    }
};

// ────────────────────────────────────────────────────────────
//  Struct: ScanConfig — cấu hình toàn bộ scanner
// ────────────────────────────────────────────────────────────
struct ScanConfig {
    // Target process
    DWORD       targetPID        = 0;
    std::string processName      = "RobloxPlayerBeta.exe";
    std::string moduleName       = "";           // "" = main module

    // Memory scan options
    bool        scanReadOnly     = true;         // Scan PAGE_READONLY
    bool        scanExecutable   = false;        // Scan PAGE_EXECUTE_*
    size_t      chunkSize        = 4 * 1024 * 1024;   // 4 MB/chunk
    size_t      minNameLen       = 5;            // Tên flag tối thiểu
    size_t      maxNameLen       = 256;          // Tên flag tối đa
    size_t      maxValueLen      = 1024;         // Giá trị string tối đa

    // Pattern scan
    bool        usePatternScan   = true;         // Dùng signature scan
    bool        useStringSearch  = true;         // Dùng string-based search

    // Filter
    std::vector<std::string> prefixes = {
        "FFlag", "FInt", "FString", "FLog",
        "DFFlag", "DFInt", "DFString",
        "SFFlag", "SFInt"
    };

    // Export
    bool        exportJson       = true;
    bool        exportCsv        = true;
    bool        exportCppHeader  = true;
    std::string outputDir        = ".";          // Thư mục output

    // Logging
    bool        verbose          = false;
    bool        logToFile        = false;
    std::string logFile          = "fflag_scan.log";
};

// ────────────────────────────────────────────────────────────
//  Struct: ScanStats — thống kê sau khi scan
// ────────────────────────────────────────────────────────────
struct ScanStats {
    size_t  bytesScanned    = 0;
    size_t  regionsScanned  = 0;
    size_t  patternsMatched = 0;
    size_t  stringsFound    = 0;
    size_t  flagsTotal      = 0;
    size_t  duplicatesSkipped = 0;
    std::chrono::milliseconds elapsed{0};
    std::unordered_map<std::string, int> typeCounts;

    [[nodiscard]] double elapsedMs() const noexcept {
        return static_cast<double>(elapsed.count());
    }
    [[nodiscard]] double mbScanned() const noexcept {
        return static_cast<double>(bytesScanned) / (1024.0 * 1024.0);
    }
};

// ────────────────────────────────────────────────────────────
//  Struct: DumpResult — kết quả toàn bộ dump session
// ────────────────────────────────────────────────────────────
struct DumpResult {
    std::vector<FlagEntry>  flags;
    ScanStats               stats;
    bool                    success = false;
    std::string             error;

    [[nodiscard]] bool empty() const noexcept { return flags.empty(); }

    // Lọc theo kind
    [[nodiscard]] std::vector<FlagEntry> filterByKind(FlagKind k) const {
        std::vector<FlagEntry> out;
        for (const auto& f : flags)
            if (f.kind == k) out.push_back(f);
        return out;
    }
};

} // namespace FFlag
