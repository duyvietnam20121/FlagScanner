#pragma once
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <vector>
#include <string>
#include <optional>
#include <cstdint>
#include "FlagTypes.hpp"
#include "ProcessHandle.hpp"
#include "Logger.hpp"

// ============================================================
//  FlagListWalker.hpp
//  Walk Roblox FFlagList trực tiếp thay vì scan toàn bộ memory.
//
//  Roblox FFlag registry layout (x64, version-ad5d3e29):
//
//   moduleBase + FFlagListRVA
//       │
//       └─► FlagRegistryPtr  (uintptr_t*)
//               │
//               └─► FlagRegistry {
//                     uintptr_t* begin;   // +0x00 → array of FlagObject*
//                     uintptr_t* end;     // +0x08
//                     uintptr_t* cap;     // +0x10  (nếu là std::vector)
//                   }
//
//   FlagObject* layout (mỗi entry trong array):
//       +0x00  namePtr    → char* tên flag ("FFlagFoo\0")
//       +0x30  ValueGetSet→ accessor offset (vtable-relative)
//       +0xC0  FlagToValue→ con trỏ tới vùng chứa giá trị thực
//
//  Cách tìm FFlagListRVA nếu chưa biết:
//  1. Dùng CheatEngine: scan string "FFlag" → tìm struct ref → trace xref
//  2. Dùng x64dbg: bp trên FlagRegistry::register() → xem rcx
//  3. Dùng hàm probeAndFind() bên dưới để auto-probe một list RVA mẫu
// ============================================================

namespace FFlag {

// ─────────────────────────────────────────────────────────────
//  Struct: RegistryOffsets — các offset có thể thay đổi theo version
// ─────────────────────────────────────────────────────────────
struct RegistryOffsets {
    // RVA của FFlagList từ module base
    // Cập nhật mỗi khi Roblox update — dùng probeAndFind() để tự tìm
    uintptr_t FFlagListRVA   = 0x8100E00;  // version-ad5d3e29

    // Layout trong mỗi FlagObject
    uint32_t  nameOffset     = 0x00;   // offset → char* tên
    uint32_t  valueGetSet    = 0x30;   // offset → accessor
    uint32_t  flagToValue    = 0xC0;   // offset → value ptr

    // Layout của FlagRegistry (std::vector-like)
    uint32_t  beginPtrOffset = 0x00;   // offset trong registry → begin ptr
    uint32_t  endPtrOffset   = 0x08;   // offset trong registry → end ptr

    // Sanity limits
    size_t    maxFlagCount   = 100000; // vượt quá → có thể sai offset
    size_t    maxNameLen     = 256;
};

// ─────────────────────────────────────────────────────────────
//  Class: FlagListWalker
// ─────────────────────────────────────────────────────────────
class FlagListWalker {
public:
    explicit FlagListWalker(RegistryOffsets offsets = {})
        : off_(offsets) {}

    // ── Walk toàn bộ FFlagList ────────────────────────────
    // moduleBase: proc.getMainModule()->base
    [[nodiscard]] std::vector<FlagEntry>
    walkAll(const ProcessHandle& proc,
            uintptr_t            moduleBase,
            const std::vector<std::string>& prefixes) const
    {
        std::vector<FlagEntry> results;

        // ── 1. Đọc con trỏ FlagRegistry ──────────────────
        uintptr_t registryAddr = moduleBase + off_.FFlagListRVA;
        LOG_DEBUG("FlagRegistry @ 0x%llx (base=0x%llx + RVA=0x%llx)",
                  registryAddr, moduleBase, off_.FFlagListRVA);

        // Registry có thể là trực tiếp hoặc qua một indirection
        // Thử đọc begin/end trực tiếp trước
        auto beginPtr = proc.readValue<uintptr_t>(registryAddr + off_.beginPtrOffset);
        auto endPtr   = proc.readValue<uintptr_t>(registryAddr + off_.endPtrOffset);

        if (!beginPtr || !endPtr) {
            LOG_ERROR("Cannot read FlagRegistry at 0x%llx", registryAddr);
            return results;
        }

        uintptr_t begin = *beginPtr;
        uintptr_t end   = *endPtr;

        // Sanity check
        if (begin == 0 || end == 0 || end < begin) {
            LOG_WARN("Invalid registry pointers: begin=0x%llx end=0x%llx", begin, end);
            // Thử một tầng indirection nữa
            auto indirected = proc.readValue<uintptr_t>(registryAddr);
            if (!indirected || *indirected == 0) {
                LOG_ERROR("Indirection also failed — offset có thể sai");
                return results;
            }
            registryAddr = *indirected;
            beginPtr = proc.readValue<uintptr_t>(registryAddr + off_.beginPtrOffset);
            endPtr   = proc.readValue<uintptr_t>(registryAddr + off_.endPtrOffset);
            if (!beginPtr || !endPtr) return results;
            begin = *beginPtr;
            end   = *endPtr;
        }

        // Tính số entry (mỗi entry là một uintptr_t = 8 bytes trên x64)
        size_t count = (end - begin) / sizeof(uintptr_t);
        if (count == 0 || count > off_.maxFlagCount) {
            LOG_WARN("Suspicious flag count: %zu (begin=0x%llx end=0x%llx)",
                     count, begin, end);
            return results;
        }

        LOG_INFO("FFlagList: %zu entries @ [0x%llx — 0x%llx]", count, begin, end);

        // ── 2. Đọc toàn bộ array một lần (nhanh hơn RPM từng entry) ──
        std::vector<uintptr_t> flagPtrs(count);
        size_t bytesRead = proc.readMemory(
            begin, flagPtrs.data(), count * sizeof(uintptr_t));

        size_t actualCount = bytesRead / sizeof(uintptr_t);
        if (actualCount == 0) {
            LOG_ERROR("Cannot read flag pointer array");
            return results;
        }
        if (actualCount < count) {
            LOG_WARN("Partial read: got %zu / %zu pointers", actualCount, count);
            flagPtrs.resize(actualCount);
        }

        results.reserve(actualCount);
        size_t skipped = 0;

        // ── 3. Walk từng FlagObject* ──────────────────────
        for (size_t i = 0; i < flagPtrs.size(); ++i) {
            uintptr_t objPtr = flagPtrs[i];
            if (objPtr == 0) { ++skipped; continue; }

            auto entry = parseEntry(proc, objPtr, moduleBase, prefixes);
            if (!entry) { ++skipped; continue; }

            results.push_back(std::move(*entry));

            // Progress mỗi 1000 flags
            if (i % 1000 == 0 && i > 0) {
                Logger::instance().progress(i, actualCount, "WALK");
            }
        }
        Logger::instance().progress(actualCount, actualCount, "WALK");

        LOG_OK("Walked %zu valid flags (%zu skipped)", results.size(), skipped);
        return results;
    }

    // ── Probe: thử xác định layout tự động từ một offset mẫu ──
    // Dùng khi biết địa chỉ một FlagObject cụ thể (từ Cheat Engine)
    // để reverse engineer các offset nameOffset, flagToValue
    struct ProbeResult {
        uintptr_t detectedNameOffset  = 0;
        uintptr_t detectedValueOffset = 0;
        std::string firstName;
        bool success = false;
    };

    [[nodiscard]] ProbeResult
    probeObject(const ProcessHandle& proc,
                uintptr_t            knownFlagObjAddr) const
    {
        ProbeResult r;
        LOG_INFO("Probing FlagObject @ 0x%llx", knownFlagObjAddr);

        // Đọc 0x100 bytes đầu của object để phân tích
        std::vector<uint8_t> buf(0x100);
        size_t got = proc.readMemory(knownFlagObjAddr, buf.data(), buf.size());
        if (got < 0x10) {
            LOG_ERROR("Cannot read object memory");
            return r;
        }

        // Tìm offset nào chứa con trỏ tới chuỗi bắt đầu bằng "F"
        for (size_t off = 0; off + 8 <= got; off += 8) {
            uintptr_t candidate = *reinterpret_cast<uintptr_t*>(&buf[off]);
            if (candidate < 0x10000) continue;  // quá nhỏ, không phải pointer

            auto str = proc.readString(candidate, 64);
            if (!str) continue;

            // Kiểm tra xem có phải tên FFlag không
            bool isFlag = false;
            static const char* prefixArr[] = {
                "FFlag","FInt","FString","FLog",
                "DFFlag","DFInt","DFString","SFFlag","SFInt"
            };
            for (auto* pfx : prefixArr) {
                if (str->rfind(pfx, 0) == 0 && str->size() > strlen(pfx)) {
                    isFlag = true; break;
                }
            }

            if (isFlag) {
                r.detectedNameOffset = off;
                r.firstName = *str;
                LOG_OK("Detected nameOffset = 0x%llx → \"%s\"",
                       off, str->c_str());
                r.success = true;

                // Tìm valueOffset: thường là pointer ngay sau namePtr
                for (size_t voff = off + 8; voff + 8 <= got; voff += 8) {
                    uintptr_t vcandidate = *reinterpret_cast<uintptr_t*>(&buf[voff]);
                    if (vcandidate >= 0x10000) {
                        r.detectedValueOffset = voff;
                        LOG_DEBUG("Possible valueOffset = 0x%llx (ptr=0x%llx)",
                                  voff, vcandidate);
                        break;
                    }
                }
                break;
            }
        }

        if (!r.success) {
            LOG_WARN("Could not detect flag layout — dump raw bytes:");
            for (size_t off = 0; off + 8 <= got && off < 0x40; off += 8) {
                uintptr_t val = *reinterpret_cast<uintptr_t*>(&buf[off]);
                LOG_DEBUG("  +0x%02zx : 0x%016llx", off, val);
            }
        }
        return r;
    }

    // Cập nhật offset sau khi probe
    void setOffsets(const RegistryOffsets& o) { off_ = o; }
    [[nodiscard]] const RegistryOffsets& offsets() const noexcept { return off_; }

private:
    RegistryOffsets off_;

    // ── Parse một FlagObject tại địa chỉ objPtr ───────────
    [[nodiscard]] std::optional<FlagEntry>
    parseEntry(const ProcessHandle&             proc,
               uintptr_t                        objPtr,
               uintptr_t                        moduleBase,
               const std::vector<std::string>&  prefixes) const
    {
        // Đọc namePtr
        auto namePtr = proc.readValue<uintptr_t>(objPtr + off_.nameOffset);
        if (!namePtr || *namePtr == 0) return std::nullopt;

        // Đọc tên
        auto name = proc.readString(*namePtr, off_.maxNameLen);
        if (!name || name->empty()) return std::nullopt;

        // Validate prefix
        FlagKind kind = FlagKind::Unknown;
        for (const auto& pfx : prefixes) {
            if (name->rfind(pfx, 0) == 0 && name->size() > pfx.size()) {
                kind = prefixToKind(pfx);
                break;
            }
        }
        if (kind == FlagKind::Unknown) return std::nullopt;

        // Đọc value pointer
        uintptr_t valuePtr = 0;
        if (auto vp = proc.readValue<uintptr_t>(objPtr + off_.flagToValue))
            valuePtr = *vp;

        // Đọc giá trị
        std::string value = readValue(proc, valuePtr, kind);

        FlagEntry entry;
        entry.name     = std::move(*name);
        entry.kind     = kind;
        entry.address  = objPtr;
        entry.rva      = (objPtr >= moduleBase) ? (objPtr - moduleBase) : 0;
        entry.namePtr  = *namePtr;
        entry.valuePtr = valuePtr;
        entry.value    = std::move(value);

        return entry;
    }

    // ── Đọc giá trị theo kind ─────────────────────────────
    std::string readValue(const ProcessHandle& proc,
                          uintptr_t            valuePtr,
                          FlagKind             kind) const
    {
        if (valuePtr == 0) return "<null>";

        switch (kind) {
        case FlagKind::FFlag:
        case FlagKind::DFFlag:
        case FlagKind::SFFlag: {
            if (auto v = proc.readValue<uint8_t>(valuePtr))
                return (*v != 0) ? "true" : "false";
            break;
        }
        case FlagKind::FInt:
        case FlagKind::DFInt:
        case FlagKind::SFInt:
        case FlagKind::FLog: {
            if (auto v = proc.readValue<int32_t>(valuePtr))
                return std::to_string(*v);
            break;
        }
        case FlagKind::FString:
        case FlagKind::DFString: {
            // Thử đọc std::string SSO layout: [data_ptr | size | cap]
            auto strPtr = proc.readValue<uintptr_t>(valuePtr);
            if (strPtr && *strPtr != 0) {
                if (auto s = proc.readString(*strPtr, 1024))
                    return '"' + *s + '"';
            }
            // Fallback: inline buffer (SSO short string ≤15 chars)
            if (auto s = proc.readString(valuePtr, 16))
                if (!s->empty()) return '"' + *s + '"';
            break;
        }
        default: break;
        }
        return "<err>";
    }
};

} // namespace FFlag