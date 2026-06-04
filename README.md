# FFlag Scanner / Dumper v2.0
**Roblox FFlag Research Tool — C++20, Windows x64**

---

## Architecture

```
FFlag::
├── FlagTypes.hpp       — Kiểu dữ liệu (FlagKind enum, FlagEntry, ScanConfig, ...)
├── Logger.hpp          — Thread-safe logger, ANSI color, level filter, file log
├── ProcessHandle.hpp   — RAII Win32 process handle, RPM, module enum
├── PatternMatcher.hpp  — Boyer-Moore-Horspool + wildcard, IDA-style pattern parse
├── FlagScanner.hpp     — Pipeline: open → query regions → scan chunks → parse
└── Exporter.hpp        — JSON / CSV / C++ header export
```

---

## Build

```bat
mkdir build && cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
.\bin\FlagScanner.exe --help
```

---

## Usage

```
FlagScanner.exe [options]

--pid <PID>          Target PID (mặc định: auto tìm theo --process)
--process <name>     Tên process (mặc định: RobloxPlayerBeta.exe)
--module <name>      Module cụ thể để scan (mặc định: main module)
--outdir <path>      Thư mục output (mặc định: .)
--no-json            Tắt export JSON
--no-csv             Tắt export CSV
--no-header          Tắt export C++ header
--no-pattern         Tắt signature/pattern scan
--no-strings         Tắt string-based scan
--no-readonly        Bỏ qua vùng PAGE_READONLY
--exec               Scan cả vùng executable
--chunk <MB>         Chunk size khi đọc memory (mặc định: 4)
--verbose / -v       Debug logging
--logfile <path>     Ghi log ra file
--list-processes     Liệt kê process đang chạy rồi thoát
```

### Ví dụ

```bat
# Scan và export tất cả
FlagScanner.exe --verbose --outdir ./output

# Chỉ JSON, bỏ CSV
FlagScanner.exe --pid 12345 --no-csv --no-header

# Scan process khác
FlagScanner.exe --process RobloxStudio.exe --outdir C:\dumps
```

---

## Output

### JSON (`fflag_RobloxPlayerBeta_YYYYMMDD_HHMMSS.json`)
```json
{
  "meta": {
    "generated": "2025-01-15 14:30:00",
    "total_flags": 1247,
    "elapsed_ms": 842.5,
    "mb_scanned": 312.44,
    "type_counts": { "FFlag": 834, "FInt": 213, ... }
  },
  "flags": [
    {
      "name":      "FFlagMyFeature",
      "type":      "FFlag",
      "value":     "true",
      "address":   "0x00007FF6AABBCCDD",
      "rva":       "0x000000001234ABCD",
      "name_ptr":  "0x00007FF6AABBCCDD",
      "value_ptr": "0x00007FF6AABBCCEE"
    }
  ]
}
```

### CSV (`fflag_*.csv`)
```
Name,Type,Value,Address,RVA,NamePtr,ValuePtr
FFlagMyFeature,FFlag,true,0x...,0x...,0x...,0x...
```

### C++ Header (`fflag_*_offsets.hpp`)
```cpp
namespace FFlags {

// RVA constants — dùng trực tiếp trong code
constexpr uintptr_t k_FFlagMyFeature   = 0x000000001234ABCDULL;  // true

// Runtime lookup
inline const std::unordered_map<std::string_view, uintptr_t>& getFlagRvaMap();
inline const std::unordered_map<std::string_view, const char*>& getFlagTypeMap();

} // namespace FFlags
```

---

## Cải tiến so với v1

| Feature | v1 | v2 |
|---|---|---|
| Type safety | `std::string type` | `FlagKind` enum class |
| Process handle | Raw HANDLE | RAII `ProcessHandle` |
| Pattern scan | ❌ | ✅ Boyer-Moore-Horspool + wildcard |
| IDA patterns | ❌ | ✅ `"48 8B 05 ?? ?? ?? ??"` |
| Logger | `bool verbose` | Thread-safe, ANSI color, levels |
| Export | ❌ | ✅ JSON + CSV + C++ header |
| Error handling | ❌ | ✅ `std::system_error`, RAII |
| Memory read | Monolithic | Chunked + region query |
| Dedup | ❌ | ✅ `unordered_set` |
| Stats | Basic | `ScanStats` đầy đủ |
| CLI | ❌ | ✅ Arg parser đầy đủ |

---

## Lưu ý pháp lý

Tool này dành cho mục đích **nghiên cứu học thuật**.  
Việc sử dụng phải tuân thủ Terms of Service của Roblox.
