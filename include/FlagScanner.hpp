#pragma once
// NOMINMAX phải define trước mọi Windows header để chặn macro min/max
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <vector>
#include <unordered_set>
#include <chrono>
#include <algorithm>
#include "FlagTypes.hpp"
#include "ProcessHandle.hpp"
#include "PatternMatcher.hpp"
#include "Logger.hpp"

// ============================================================
//  FFlag Scanner/Dumper — FlagScanner
//  File: FlagScanner.hpp
//  Pipeline: open process → map module → scan regions → parse
// ============================================================

namespace FFlag {

class FlagScanner {
public:
    explicit FlagScanner(ScanConfig config)
        : config_(std::move(config)) {}

    // ── Entry point: thực hiện toàn bộ scan ──────────────
    [[nodiscard]] DumpResult scan() {
        DumpResult result;
        auto t0 = std::chrono::high_resolution_clock::now();

        try {
            result = doScan();
        } catch (const std::exception& ex) {
            result.success = false;
            result.error   = ex.what();
            LOG_ERROR("Scan failed: %s", ex.what());
        }

        auto t1 = std::chrono::high_resolution_clock::now();
        result.stats.elapsed =
            std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0);

        return result;
    }

private:
    ScanConfig config_;

    // ── Main scan pipeline ────────────────────────────────
    DumpResult doScan() {
        DumpResult result;

        // ── 1. Tìm PID ──────────────────────────────────
        DWORD pid = config_.targetPID;
        if (pid == 0) {
            LOG_INFO("Searching for process: %s", config_.processName.c_str());
            pid = ProcessHandle::findPIDByName(config_.processName);
            if (pid == 0) {
                result.error = "Process not found: " + config_.processName;
                LOG_ERROR("%s", result.error.c_str());
                return result;
            }
        }
        LOG_OK("Found PID: %lu", pid);

        // ── 2. Mở process ────────────────────────────────
        ProcessHandle proc(pid);

        // ── 3. Xác định module cần scan ──────────────────
        ModuleInfo module;
        if (config_.moduleName.empty()) {
            auto m = proc.getMainModule();
            if (!m) {
                result.error = "Cannot get main module";
                LOG_ERROR("%s", result.error.c_str());
                return result;
            }
            module = *m;
        } else {
            auto m = proc.getModule(config_.moduleName);
            if (!m) {
                result.error = "Module not found: " + config_.moduleName;
                LOG_ERROR("%s", result.error.c_str());
                return result;
            }
            module = *m;
        }

        LOG_INFO("Target module: %s | Base=0x%llx | Size=%.2f MB",
                 module.name.c_str(),
                 module.base,
                 static_cast<double>(module.size) / (1024.0 * 1024.0));

        // ── 4. Liệt kê regions có thể đọc ───────────────
        auto regions = proc.queryRegions(
            module.base, module.size,
            config_.scanReadOnly,
            config_.scanExecutable);

        LOG_INFO("Scanning %zu memory regions...", regions.size());

        // ── 5. Compile patterns ──────────────────────────
        std::vector<CompiledPattern> patterns;
        if (config_.usePatternScan) {
            patterns = PatternMatcher::robloxPatterns();
            LOG_DEBUG("Loaded %zu built-in patterns", patterns.size());
        }

        // ── 6. Scan từng region ──────────────────────────
        std::unordered_set<uintptr_t> seenAddresses;  // Dedup
        std::vector<uint8_t> chunkBuf;
        chunkBuf.reserve(config_.chunkSize);

        for (size_t ri = 0; ri < regions.size(); ++ri) {
            const auto& region = regions[ri];
            scanRegion(proc, region, module.base,
                       patterns, seenAddresses,
                       result, chunkBuf);

            result.stats.regionsScanned++;
            result.stats.bytesScanned += region.size;

            // Progress mỗi 10 regions
            if (config_.verbose && ri % 10 == 0) {
                Logger::instance().progress(ri + 1, regions.size(), "SCAN");
            }
        }

        if (config_.verbose)
            Logger::instance().progress(regions.size(), regions.size(), "SCAN");

        // ── 7. Sort kết quả theo RVA ─────────────────────
        std::sort(result.flags.begin(), result.flags.end(),
            [](const FlagEntry& a, const FlagEntry& b) {
                return a.rva < b.rva;
            });

        // ── 8. Tính type counts ──────────────────────────
        for (const auto& f : result.flags) {
            result.stats.typeCounts[f.typeName()]++;
        }

        result.stats.flagsTotal       = result.flags.size();
        result.stats.duplicatesSkipped = seenAddresses.size() - result.flags.size();
        result.success = true;

        LOG_OK("Scan complete: %zu flags found (%.2f MB in %.1f ms)",
               result.flags.size(),
               result.stats.mbScanned(),
               result.stats.elapsedMs());
        printTypeSummary(result.stats);

        return result;
    }

    // ── Scan một memory region ────────────────────────────
    void scanRegion(const ProcessHandle&              proc,
                    const ProcessHandle::MemRegion&   region,
                    uintptr_t                         moduleBase,
                    const std::vector<CompiledPattern>& patterns,
                    std::unordered_set<uintptr_t>&    seen,
                    DumpResult&                       result,
                    std::vector<uint8_t>&             chunkBuf)
    {
        // Đọc region theo chunks để tiết kiệm RAM
        size_t offset = 0;
        while (offset < region.size) {
            size_t toRead = (config_.chunkSize < region.size - offset)
                          ? config_.chunkSize : region.size - offset;
            chunkBuf.resize(toRead);

            size_t bytesRead = proc.readMemory(region.base + offset,
                                               chunkBuf.data(), toRead);
            if (bytesRead == 0) {
                offset += toRead;
                continue;
            }
            chunkBuf.resize(bytesRead);

            uintptr_t chunkBase = region.base + offset;

            // ── String-based search ──────────────────────
            if (config_.useStringSearch) {
                auto nameOffsets = PatternMatcher::findFlagNames(
                    chunkBuf.data(), chunkBuf.size(),
                    config_.prefixes,
                    config_.minNameLen,
                    config_.maxNameLen);

                for (size_t nameOff : nameOffsets) {
                    uintptr_t nameAddr = chunkBase + nameOff;

                    // Đọc tên flag từ buffer (đã có trong chunk)
                    std::string flagName;
                    flagName.reserve(64);
                    size_t k = nameOff;
                    while (k < chunkBuf.size() && chunkBuf[k] != '\0' &&
                           flagName.size() < config_.maxNameLen)
                    {
                        flagName += static_cast<char>(chunkBuf[k++]);
                    }

                    if (flagName.empty()) continue;

                    // Dedup theo nameAddr
                    if (seen.count(nameAddr)) {
                        result.stats.duplicatesSkipped++;
                        continue;
                    }
                    seen.insert(nameAddr);

                    FlagEntry entry = buildEntry(
                        flagName, nameAddr, 0, moduleBase, proc);

                    if (entry.kind != FlagKind::Unknown)
                        result.flags.push_back(std::move(entry));
                }
                result.stats.stringsFound += nameOffsets.size();
            }

            // ── Pattern-based search ─────────────────────
            if (config_.usePatternScan) {
                for (const auto& pat : patterns) {
                    auto matches = PatternMatcher::findAll(
                        chunkBuf.data(), chunkBuf.size(), pat);

                    for (size_t matchOff : matches) {
                        result.stats.patternsMatched++;

                        // Đọc con trỏ tên từ offset trong pattern
                        uintptr_t ptrAddr = chunkBase + matchOff
                                          + pat.nameOffset;
                        auto namePtr = proc.readValue<uintptr_t>(ptrAddr);
                        if (!namePtr || *namePtr == 0) continue;

                        auto nameStr = proc.readString(*namePtr,
                                           config_.maxNameLen);
                        if (!nameStr) continue;

                        uintptr_t nameAddr = *namePtr;
                        if (seen.count(nameAddr)) continue;

                        // Validate prefix
                        bool validPrefix = false;
                        for (const auto& pfx : config_.prefixes) {
                            if (nameStr->rfind(pfx, 0) == 0) {
                                validPrefix = true;
                                break;
                            }
                        }
                        if (!validPrefix) continue;

                        seen.insert(nameAddr);

                        uintptr_t valPtrAddr = chunkBase + matchOff
                                             + pat.valueOffset;
                        auto valPtr = proc.readValue<uintptr_t>(valPtrAddr);

                        FlagEntry entry = buildEntry(
                            *nameStr, nameAddr,
                            valPtr.value_or(0),
                            moduleBase, proc);

                        if (entry.kind != FlagKind::Unknown)
                            result.flags.push_back(std::move(entry));
                    }
                }
            }

            offset += bytesRead;
        }
    }

    // ── Build FlagEntry từ tên + địa chỉ ─────────────────
    FlagEntry buildEntry(const std::string& name,
                         uintptr_t          nameAddr,
                         uintptr_t          valuePtr,
                         uintptr_t          moduleBase,
                         const ProcessHandle& proc) const
    {
        FlagEntry entry;
        entry.name     = name;
        entry.namePtr  = nameAddr;
        entry.address  = nameAddr;
        entry.rva      = (nameAddr >= moduleBase) ? (nameAddr - moduleBase) : 0;
        entry.valuePtr = valuePtr;

        // Xác định kind từ prefix
        for (const auto& pfx : config_.prefixes) {
            if (name.rfind(pfx, 0) == 0) {
                entry.kind = prefixToKind(pfx);
                break;
            }
        }

        // Đọc giá trị nếu có con trỏ
        if (valuePtr != 0) {
            entry.value = readValue(proc, valuePtr, entry.kind);
        } else {
            entry.value = "<unknown>";
        }

        LOG_DEBUG("Found: [%s] %s @ RVA=0x%llx val=%s",
                  entry.typeName(), name.c_str(),
                  entry.rva, entry.value.c_str());

        return entry;
    }

    // ── Đọc và stringify value theo kind ─────────────────
    std::string readValue(const ProcessHandle& proc,
                          uintptr_t            valuePtr,
                          FlagKind             kind) const
    {
        switch (kind) {
        case FlagKind::FFlag:
        case FlagKind::DFFlag:
        case FlagKind::SFFlag: {
            auto v = proc.readValue<uint8_t>(valuePtr);
            if (v) return (*v != 0) ? "true" : "false";
            break;
        }
        case FlagKind::FInt:
        case FlagKind::DFInt:
        case FlagKind::SFInt:
        case FlagKind::FLog: {
            auto v = proc.readValue<int32_t>(valuePtr);
            if (v) return std::to_string(*v);
            break;
        }
        case FlagKind::FString:
        case FlagKind::DFString: {
            // Roblox std::string layout: ptr + size + capacity (SSO)
            // Thử đọc trực tiếp hoặc dereference con trỏ
            auto strPtr = proc.readValue<uintptr_t>(valuePtr);
            if (strPtr && *strPtr != 0) {
                auto s = proc.readString(*strPtr, config_.maxValueLen);
                if (s) return '"' + *s + '"';
            }
            // Fallback: đọc inline buffer
            auto s = proc.readString(valuePtr, 32);
            if (s && !s->empty()) return '"' + *s + '"';
            break;
        }
        default: break;
        }
        return "<read_error>";
    }

    // ── In summary sau scan ───────────────────────────────
    static void printTypeSummary(const ScanStats& stats) {
        LOG_INFO("─── Type Summary ───────────────────────");
        for (const auto& [type, count] : stats.typeCounts) {
            LOG_INFO("  %-12s : %d", type.c_str(), count);
        }
        LOG_INFO("  %-12s : %.2f MB scanned, %zu regions",
                 "Coverage",
                 stats.mbScanned(),
                 stats.regionsScanned);
    }
};

} // namespace FFlag