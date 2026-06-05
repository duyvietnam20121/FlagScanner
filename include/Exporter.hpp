#pragma once
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <filesystem>
#include "FlagTypes.hpp"
#include "Logger.hpp"

// ============================================================
//  FFlag Scanner/Dumper — Exporter
//  File: Exporter.hpp
//  Export DumpResult → JSON, CSV, C++ header
// ============================================================

namespace FFlag {
namespace fs = std::filesystem;

class Exporter {
public:
    // ── Export toàn bộ theo ScanConfig ───────────────────
    static bool exportAll(const DumpResult&  result,
                          const ScanConfig&  config)
    {
        if (!result.success || result.empty()) {
            LOG_WARN("Nothing to export (empty or failed result)");
            return false;
        }

        // Đảm bảo thư mục output tồn tại
        std::error_code ec;
        fs::create_directories(config.outputDir, ec);
        if (ec) {
            LOG_ERROR("Cannot create output dir '%s': %s",
                      config.outputDir.c_str(), ec.message().c_str());
            return false;
        }

        std::string stem = makeFileStem(config.processName);
        bool ok = true;

        if (config.exportJson)
            ok &= exportJson(result, config.outputDir + "/" + stem + ".json");

        if (config.exportCsv)
            ok &= exportCsv(result, config.outputDir + "/" + stem + ".csv");

        if (config.exportCppHeader)
            ok &= exportCppHeader(result, config.outputDir + "/" + stem + "_offsets.hpp");

        return ok;
    }

    // ────────────────────────────────────────────────────
    //  JSON export (không cần thư viện ngoài)
    // ────────────────────────────────────────────────────
    static bool exportJson(const DumpResult& result,
                           const std::string& path)
    {
        std::ofstream f(path);
        if (!f) {
            LOG_ERROR("Cannot open for write: %s", path.c_str());
            return false;
        }

        f << "{\n";
        f << "  \"meta\": {\n";
        f << "    \"roblox_version\": \"" << result.clientVersion << "\",\n";
        f << "    \"generated\": \"" << currentTimestamp() << "\",\n";
        f << "    \"total_flags\": " << result.flags.size() << ",\n";
        f << "    \"elapsed_ms\": " << result.stats.elapsedMs() << ",\n";
        f << "    \"mb_scanned\": "
          << std::fixed << std::setprecision(2) << result.stats.mbScanned() << ",\n";
        f << "    \"regions_scanned\": " << result.stats.regionsScanned << ",\n";

        // Type counts
        f << "    \"type_counts\": {\n";
        bool first = true;
        for (const auto& [k, v] : result.stats.typeCounts) {
            if (!first) f << ",\n";
            f << "      \"" << jsonEscape(k) << "\": " << v;
            first = false;
        }
        f << "\n    }\n";
        f << "  },\n";

        // Flags array
        f << "  \"flags\": [\n";
        for (size_t i = 0; i < result.flags.size(); ++i) {
            const auto& flag = result.flags[i];
            f << "    {\n";
            f << "      \"name\":       \"" << jsonEscape(flag.name) << "\",\n";
            f << "      \"type\":       \"" << flag.typeName() << "\",\n";
            f << "      \"value\":      \"" << jsonEscape(flag.value) << "\",\n";
            f << "      \"address\":    \"0x" << hex16(flag.address) << "\",\n";
            f << "      \"rva\":        \"0x" << hex16(flag.rva) << "\",\n";
            f << "      \"name_ptr\":   \"0x" << hex16(flag.namePtr) << "\",\n";
            f << "      \"value_ptr\":  \"0x" << hex16(flag.valuePtr) << "\"\n";
            f << "    }";
            if (i + 1 < result.flags.size()) f << ",";
            f << "\n";
        }
        f << "  ]\n";
        f << "}\n";

        f.flush();
        LOG_OK("JSON exported: %s (%zu flags)", path.c_str(), result.flags.size());
        return f.good();
    }

    // ────────────────────────────────────────────────────
    //  CSV export
    // ────────────────────────────────────────────────────
    static bool exportCsv(const DumpResult& result,
                           const std::string& path)
    {
        std::ofstream f(path);
        if (!f) {
            LOG_ERROR("Cannot open for write: %s", path.c_str());
            return false;
        }

        // Header
        f << "Name,Type,Value,Address,RVA,NamePtr,ValuePtr\n";

        for (const auto& flag : result.flags) {
            f << csvQuote(flag.name)  << ","
              << flag.typeName()      << ","
              << csvQuote(flag.value) << ","
              << "0x" << hex16(flag.address) << ","
              << "0x" << hex16(flag.rva)     << ","
              << "0x" << hex16(flag.namePtr) << ","
              << "0x" << hex16(flag.valuePtr) << "\n";
        }

        f.flush();
        LOG_OK("CSV exported: %s (%zu rows)", path.c_str(), result.flags.size());
        return f.good();
    }

    // ────────────────────────────────────────────────────
    //  C++ Header export — offsets dùng trực tiếp trong code
    // ────────────────────────────────────────────────────
    static bool exportCppHeader(const DumpResult& result,
                                  const std::string& path)
    {
        std::ofstream f(path);
        if (!f) {
            LOG_ERROR("Cannot open for write: %s", path.c_str());
            return false;
        }

        // ── Header giống format của Sins dump ────────────
        f << "// Roblox Version - " << result.clientVersion << "\n";
        f << "// Total flags: " << formatNumber(result.flags.size()) << "\n";
        f << "// Dumped at " << currentTimestamp() << "\n";
        f << "\n";
        f << "#pragma once\n";
        f << "#include <cstdint>\n\n";
        f << "namespace FFlagOffsets\n{\n";

        // Walk offsets (từ FlagListWalker)
        f << "    uintptr_t FFlagList   = 0x"
          << std::hex << result.stats.flagListRVA << ";\n";
        f << "    uintptr_t ValueGetSet = 0x30;\n";
        f << "    uintptr_t FlagToValue = 0xC0;\n";
        f << "}\n\n";

        f << "namespace FFlags\n{\n";

        // ── Flags: format giống Sins dump ─────────────
        // uintptr_t FlagName = 0xRVA;   (tên gốc, không prefix)
        for (const auto& flag : result.flags) {
            // Bỏ prefix type khỏi tên biến: "FFlagFoo" → "FFlagFoo"
            // (giữ nguyên tên đầy đủ giống Sins)
            std::string shortName = stripTypePrefix(flag.name);
            f << "    uintptr_t " << std::left << std::setw(52) << shortName
              << " = 0x" << std::hex << flag.rva << ";\n";
        }
        f << "}\n";

        f.flush();
        LOG_OK("C++ header exported: %s (%zu constants)", path.c_str(), result.flags.size());
        return f.good();
    }

private:
    // ── Helpers ───────────────────────────────────────────

    // Format số có dấu phẩy: 13390 → "13,390"
    static std::string formatNumber(size_t n) {
        std::string s = std::to_string(n);
        int pos = static_cast<int>(s.size()) - 3;
        while (pos > 0) { s.insert(pos, ","); pos -= 3; }
        return s;
    }

    static std::string currentTimestamp() {
        std::time_t now = std::time(nullptr);
        char buf[32];
        std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
        return buf;
    }

    static std::string makeFileStem(const std::string& processName) {
        std::time_t now = std::time(nullptr);
        char ts[20];
        std::strftime(ts, sizeof(ts), "%Y%m%d_%H%M%S", std::localtime(&now));

        std::string base = processName;
        // Bỏ .exe
        auto dot = base.rfind('.');
        if (dot != std::string::npos) base = base.substr(0, dot);
        // Thay ký tự không hợp lệ
        for (char& c : base)
            if (!isalnum(static_cast<unsigned char>(c)) && c != '-') c = '_';

        return "fflag_" + base + "_" + ts;
    }

    static std::string hex16(uintptr_t v) {
        std::ostringstream ss;
        ss << std::uppercase << std::hex << std::setfill('0') << std::setw(16) << v;
        return ss.str();
    }

    // Escape JSON string
    static std::string jsonEscape(const std::string& s) {
        std::string out;
        out.reserve(s.size() + 4);
        for (char c : s) {
            switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:   out += c;      break;
            }
        }
        return out;
    }

    // CSV: bọc ngoặc kép nếu có dấu phẩy/nháy
    static std::string csvQuote(const std::string& s) {
        bool needsQuote = s.find_first_of(",\"'\n\r") != std::string::npos;
        if (!needsQuote) return s;
        std::string out = "\"";
        for (char c : s) {
            if (c == '"') out += "\"\"";
            else          out += c;
        }
        out += '"';
        return out;
    }

    // Tạo tên biến C++ hợp lệ (giữ nguyên FFlagXxx → k_FFlagXxx)
    // Giữ nguyên tên đầy đủ (FFlagFoo) — giống Sins format
    // Chỉ strip ký tự không hợp lệ cho C++ identifier
    static std::string stripTypePrefix(const std::string& name) {
        // Sins dump giữ nguyên tên gốc: "FFlagFoo", "FIntBar"
        // Chỉ đảm bảo ký tự hợp lệ cho C++ identifier
        std::string out;
        out.reserve(name.size());
        for (size_t i = 0; i < name.size(); ++i) {
            char c = name[i];
            if (isalnum(static_cast<unsigned char>(c)) || c == '_')
                out += c;
            else
                out += '_';
        }
        return out;
    }

    static std::string sanitizeCppName(const std::string& name) {
        std::string out;
        out.reserve(name.size());
        for (char c : name) {
            if (isalnum(static_cast<unsigned char>(c)) || c == '_')
                out += c;
            else
                out += '_';
        }
        return out;
    }
};

} // namespace FFlag