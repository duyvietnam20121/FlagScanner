#pragma once
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
#include "FlagListWalker.hpp"
#include "VersionReader.hpp"
#include "Logger.hpp"

// ============================================================
//  FlagScanner.hpp
//  Pipeline:
//    Method A (primary)  : FlagListWalker — walk FFlagList trực tiếp
//                          → nhanh, đầy đủ ~13,000+ flags
//    Method B (fallback) : string scan toàn bộ memory regions
//                          → dùng khi chưa biết FFlagListRVA
// ============================================================

namespace FFlag {

// Thêm vào ScanConfig — các field cho FlagListWalker
// (tách thành struct riêng để không phá vỡ ScanConfig cũ)
struct WalkerConfig {
    bool          enabled      = true;
    RegistryOffsets offsets    = {};   // FFlagListRVA + field offsets
    bool          fallbackScan = true; // Nếu walk thất bại → fallback string scan
};

class FlagScanner {
public:
    explicit FlagScanner(ScanConfig config, WalkerConfig walkerCfg = {})
        : config_(std::move(config))
        , walkerCfg_(std::move(walkerCfg)) {}

    // ── Entry point ───────────────────────────────────────
    [[nodiscard]] DumpResult scan() {
        DumpResult result;
        auto t0 = std::chrono::high_resolution_clock::now();
        try {
            result = doScan();
        } catch (const std::exception& ex) {
            result.success = false;
            result.error   = ex.what();
            LOG_ERROR("Scan exception: %s", ex.what());
        }
        auto t1 = std::chrono::high_resolution_clock::now();
        result.stats.elapsed =
            std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0);
        return result;
    }

    // ── Probe mode: tự tìm layout offset từ địa chỉ mẫu ─
    // knownObjAddr: địa chỉ một FlagObject lấy từ Cheat Engine/x64dbg
    void probe(uintptr_t knownObjAddr) {
        LOG_INFO("=== PROBE MODE ===");
        LOG_INFO("Probing FlagObject @ 0x%llx", knownObjAddr);

        DWORD pid = resolvePID();
        if (!pid) return;

        ProcessHandle proc(pid);
        FlagListWalker walker(walkerCfg_.offsets);
        auto result = walker.probeObject(proc, knownObjAddr);

        if (result.success) {
            LOG_OK("Detected layout:");
            LOG_OK("  nameOffset  = 0x%llx", result.detectedNameOffset);
            LOG_OK("  valueOffset = 0x%llx", result.detectedValueOffset);
            LOG_OK("  firstName   = \"%s\"",  result.firstName.c_str());
            LOG_INFO("Update RegistryOffsets với các giá trị trên rồi scan lại.");
        } else {
            LOG_ERROR("Probe failed — thử địa chỉ FlagObject khác");
        }
    }

private:
    ScanConfig    config_;
    WalkerConfig  walkerCfg_;

    DWORD resolvePID() {
        DWORD pid = config_.targetPID;
        if (pid == 0) {
            pid = ProcessHandle::findPIDByName(config_.processName);
            if (pid == 0) {
                LOG_ERROR("Process not found: %s", config_.processName.c_str());
                return 0;
            }
        }
        return pid;
    }

    // ── Main pipeline ─────────────────────────────────────
    DumpResult doScan() {
        DumpResult result;

        // 1. PID
        DWORD pid = resolvePID();
        if (!pid) {
            result.error = "Process not found: " + config_.processName;
            return result;
        }
        LOG_OK("PID: %lu", pid);

        // 2. Open process
        ProcessHandle proc(pid);

        // 3. Module
        ModuleInfo module;
        {
            auto m = config_.moduleName.empty()
                   ? proc.getMainModule()
                   : proc.getModule(config_.moduleName);
            if (!m) {
                result.error = "Module not found";
                LOG_ERROR("%s", result.error.c_str());
                return result;
            }
            module = *m;
        }
        LOG_INFO("Module: %s  base=0x%llx  size=%.1f MB",
                 module.name.c_str(), module.base,
                 module.size / 1048576.0);

        // ── Đọc ClientVersion từ memory ──────────────────
        result.clientVersion = VersionReader::read(proc, module.base, module.size);
        LOG_INFO("Version: %s", result.clientVersion.c_str());

        // ── METHOD A: FlagListWalker (primary) ───────────
        bool walkerSucceeded = false;
        if (walkerCfg_.enabled) {
            LOG_INFO("─── Method A: FFlagList walk ────────────────");
            FlagListWalker walker(walkerCfg_.offsets);
            auto flags = walker.walkAll(proc, module.base, config_.prefixes);

            if (!flags.empty()) {
                result.flags              = std::move(flags);
                result.stats.flagListRVA  = walkerCfg_.offsets.FFlagListRVA;
                walkerSucceeded           = true;
                LOG_OK("Method A: %zu flags", result.flags.size());
            } else {
                LOG_WARN("Method A: 0 flags — RVA mungkin sudah berubah");
                LOG_WARN("Tip: jalankan dengan --probe <addr> untuk deteksi otomatis");
            }
        }

        // ── METHOD B: string + pattern scan (fallback) ───
        if (!walkerSucceeded && walkerCfg_.fallbackScan) {
            LOG_INFO("─── Method B: full memory scan (fallback) ───");
            doMemoryScan(proc, module, result);
        }

        if (result.flags.empty()) {
            result.error = "No flags found. "
                           "Cập nhật FFlagListRVA hoặc dùng --probe.";
            LOG_ERROR("%s", result.error.c_str());
            return result;
        }

        // Sort theo RVA
        std::sort(result.flags.begin(), result.flags.end(),
            [](const FlagEntry& a, const FlagEntry& b){
                return a.rva < b.rva;
            });

        // Type counts
        for (const auto& f : result.flags)
            result.stats.typeCounts[f.typeName()]++;
        result.stats.flagsTotal = result.flags.size();
        result.success = true;

        printSummary(result);
        return result;
    }

    // ── Method B implementation ───────────────────────────
    void doMemoryScan(const ProcessHandle& proc,
                      const ModuleInfo&    module,
                      DumpResult&          result)
    {
        auto regions = proc.queryRegions(
            module.base, module.size,
            config_.scanReadOnly,
            config_.scanExecutable);

        LOG_INFO("Scanning %zu regions...", regions.size());

        std::vector<CompiledPattern> patterns;
        if (config_.usePatternScan)
            patterns = PatternMatcher::robloxPatterns();

        std::unordered_set<uintptr_t> seen;
        std::vector<uint8_t> chunk;
        chunk.reserve(config_.chunkSize);

        for (size_t ri = 0; ri < regions.size(); ++ri) {
            scanRegion(proc, regions[ri], module.base,
                       patterns, seen, result, chunk);
            result.stats.regionsScanned++;
            result.stats.bytesScanned += regions[ri].size;
            if (ri % 20 == 0)
                Logger::instance().progress(ri + 1, regions.size(), "SCAN");
        }
        Logger::instance().progress(regions.size(), regions.size(), "SCAN");
    }

    void scanRegion(const ProcessHandle&              proc,
                    const ProcessHandle::MemRegion&   region,
                    uintptr_t                         moduleBase,
                    const std::vector<CompiledPattern>& patterns,
                    std::unordered_set<uintptr_t>&    seen,
                    DumpResult&                       result,
                    std::vector<uint8_t>&             chunk)
    {
        size_t offset = 0;
        while (offset < region.size) {
            size_t toRead = (config_.chunkSize < region.size - offset)
                          ? config_.chunkSize : region.size - offset;
            chunk.resize(toRead);
            size_t got = proc.readMemory(region.base + offset, chunk.data(), toRead);
            if (got == 0) { offset += toRead; continue; }
            chunk.resize(got);
            uintptr_t chunkBase = region.base + offset;

            // String search
            if (config_.useStringSearch) {
                auto offs = PatternMatcher::findFlagNames(
                    chunk.data(), chunk.size(), config_.prefixes,
                    config_.minNameLen, config_.maxNameLen);

                for (size_t no : offs) {
                    uintptr_t nameAddr = chunkBase + no;
                    if (seen.count(nameAddr)) continue;
                    seen.insert(nameAddr);

                    std::string name;
                    for (size_t k = no; k < chunk.size() && chunk[k]; ++k)
                        name += (char)chunk[k];
                    if (name.empty()) continue;

                    FlagEntry e = makeFallbackEntry(name, nameAddr, 0, moduleBase);
                    if (e.kind != FlagKind::Unknown)
                        result.flags.push_back(std::move(e));
                }
            }

            // Pattern scan
            if (config_.usePatternScan) {
                for (const auto& pat : patterns) {
                    for (size_t mo : PatternMatcher::findAll(chunk.data(), chunk.size(), pat)) {
                        uintptr_t ptrAddr = chunkBase + mo + pat.nameOffset;
                        auto namePtr = proc.readValue<uintptr_t>(ptrAddr);
                        if (!namePtr || !*namePtr) continue;
                        if (seen.count(*namePtr)) continue;
                        auto nameStr = proc.readString(*namePtr, config_.maxNameLen);
                        if (!nameStr) continue;
                        bool valid = false;
                        for (const auto& pfx : config_.prefixes)
                            if (nameStr->rfind(pfx, 0) == 0) { valid = true; break; }
                        if (!valid) continue;
                        seen.insert(*namePtr);
                        FlagEntry e = makeFallbackEntry(*nameStr, *namePtr, 0, moduleBase);
                        if (e.kind != FlagKind::Unknown)
                            result.flags.push_back(std::move(e));
                    }
                }
            }

            offset += got;
        }
    }

    static FlagEntry makeFallbackEntry(const std::string& name,
                                       uintptr_t nameAddr,
                                       uintptr_t valuePtr,
                                       uintptr_t moduleBase)
    {
        FlagEntry e;
        e.name     = name;
        e.address  = nameAddr;
        e.rva      = (nameAddr >= moduleBase) ? (nameAddr - moduleBase) : 0;
        e.namePtr  = nameAddr;
        e.valuePtr = valuePtr;
        e.value    = "<fallback>";
        for (const auto* pfx : {"FFlag","FInt","FString","FLog",
                                  "DFFlag","DFInt","DFString","SFFlag","SFInt"})
            if (name.rfind(pfx, 0) == 0 && name.size() > strlen(pfx)) {
                e.kind = prefixToKind(pfx);
                break;
            }
        return e;
    }

    static void printSummary(const DumpResult& r) {
        LOG_OK("────────────────────────────────────────");
        LOG_OK("Total flags : %zu", r.flags.size());
        LOG_OK("Elapsed     : %.1f ms", r.stats.elapsedMs());
        LOG_OK("────────────────────────────────────────");
        for (const auto& [type, cnt] : r.stats.typeCounts)
            LOG_INFO("  %-12s : %d", type.c_str(), cnt);
    }
};

} // namespace FFlag