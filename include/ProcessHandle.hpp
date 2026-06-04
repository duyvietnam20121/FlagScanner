#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <string>
#include <vector>
#include <optional>
#include <stdexcept>
#include <system_error>
#include "FlagTypes.hpp"
#include "Logger.hpp"

// ============================================================
//  FFlag Scanner/Dumper — ProcessHandle
//  File: ProcessHandle.hpp
//  RAII wrapper: mở/đóng process, liệt kê module, đọc memory
// ============================================================

namespace FFlag {

// ────────────────────────────────────────────────────────────
//  Helper: Lấy mô tả lỗi Win32 từ error code
// ────────────────────────────────────────────────────────────
inline std::string win32Error(DWORD code = GetLastError()) {
    char buf[512] = {};
    FormatMessageA(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, code, 0, buf, sizeof(buf), nullptr);
    // Xoá newline cuối
    size_t len = strlen(buf);
    while (len > 0 && (buf[len-1] == '\n' || buf[len-1] == '\r')) buf[--len] = '\0';
    return buf;
}

// ────────────────────────────────────────────────────────────
//  Class: ProcessHandle — RAII handle + memory reader
// ────────────────────────────────────────────────────────────
class ProcessHandle {
public:
    // ── Constructor: mở theo PID ─────────────────────────
    explicit ProcessHandle(DWORD pid,
                           DWORD access = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION)
        : pid_(pid)
    {
        handle_ = OpenProcess(access, FALSE, pid);
        if (!handle_) {
            throw std::system_error(
                static_cast<int>(GetLastError()),
                std::system_category(),
                "OpenProcess PID=" + std::to_string(pid) + " failed: " + win32Error());
        }
        LOG_DEBUG("Opened process PID=%lu handle=0x%p", pid, handle_);
    }

    // ── Destructor ───────────────────────────────────────
    ~ProcessHandle() {
        if (handle_) {
            CloseHandle(handle_);
            LOG_DEBUG("Closed process handle PID=%lu", pid_);
        }
    }

    // Non-copyable, movable
    ProcessHandle(const ProcessHandle&)            = delete;
    ProcessHandle& operator=(const ProcessHandle&) = delete;

    ProcessHandle(ProcessHandle&& o) noexcept
        : handle_(o.handle_), pid_(o.pid_)
    { o.handle_ = nullptr; }

    ProcessHandle& operator=(ProcessHandle&& o) noexcept {
        if (this != &o) {
            if (handle_) CloseHandle(handle_);
            handle_ = o.handle_;
            pid_    = o.pid_;
            o.handle_ = nullptr;
        }
        return *this;
    }

    // ── Accessors ────────────────────────────────────────
    [[nodiscard]] HANDLE  raw()   const noexcept { return handle_; }
    [[nodiscard]] DWORD   pid()   const noexcept { return pid_; }
    [[nodiscard]] bool    valid() const noexcept { return handle_ != nullptr; }

    // ── ReadMemory: đọc N bytes từ địa chỉ addr ──────────
    // Trả về số bytes thực sự đọc được (0 nếu fail)
    [[nodiscard]] size_t readMemory(uintptr_t addr,
                                    void*     buffer,
                                    size_t    size) const noexcept
    {
        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(handle_,
                               reinterpret_cast<LPCVOID>(addr),
                               buffer, size, &bytesRead))
        {
            // ERROR_PARTIAL_COPY là bình thường ở vùng biên
            DWORD err = GetLastError();
            if (err != ERROR_PARTIAL_COPY)
                LOG_DEBUG("RPM fail addr=0x%llx size=%zu err=%lu", addr, size, err);
        }
        return static_cast<size_t>(bytesRead);
    }

    // ── ReadValue<T>: đọc một giá trị typed ──────────────
    template <typename T>
    [[nodiscard]] std::optional<T> readValue(uintptr_t addr) const noexcept {
        T val{};
        if (readMemory(addr, &val, sizeof(T)) == sizeof(T))
            return val;
        return std::nullopt;
    }

    // ── ReadString: đọc null-terminated string ───────────
    [[nodiscard]] std::optional<std::string>
    readString(uintptr_t addr, size_t maxLen = 512) const noexcept
    {
        if (addr == 0) return std::nullopt;
        std::string result;
        result.reserve(64);
        char ch = 0;
        for (size_t i = 0; i < maxLen; ++i) {
            if (readMemory(addr + i, &ch, 1) != 1) break;
            if (ch == '\0') return result;
            result += ch;
        }
        return std::nullopt;  // Không tìm thấy null terminator
    }

    // ── EnumModules: liệt kê tất cả module đang load ─────
    [[nodiscard]] std::vector<ModuleInfo> enumModules() const {
        std::vector<ModuleInfo> modules;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid_);
        if (snap == INVALID_HANDLE_VALUE) {
            LOG_ERROR("CreateToolhelp32Snapshot failed: %s", win32Error().c_str());
            return modules;
        }

        MODULEENTRY32W me{};
        me.dwSize = sizeof(me);
        if (Module32FirstW(snap, &me)) {
            do {
                ModuleInfo info;
                info.base = reinterpret_cast<uintptr_t>(me.modBaseAddr);
                info.size = static_cast<size_t>(me.modBaseSize);

                // Chuyển wide string → UTF-8
                info.name = wideToUtf8(me.szModule);
                info.path = wideToUtf8(me.szExePath);

                modules.push_back(std::move(info));
            } while (Module32NextW(snap, &me));
        }

        CloseHandle(snap);
        LOG_DEBUG("Enumerated %zu modules", modules.size());
        return modules;
    }

    // ── GetModule: tìm module theo tên (case-insensitive) ─
    [[nodiscard]] std::optional<ModuleInfo>
    getModule(const std::string& name) const {
        auto modules = enumModules();
        std::string nameLower = toLower(name);
        for (auto& m : modules) {
            if (toLower(m.name) == nameLower)
                return m;
        }
        return std::nullopt;
    }

    // ── GetMainModule: lấy module đầu tiên (exe chính) ───
    [[nodiscard]] std::optional<ModuleInfo> getMainModule() const {
        auto modules = enumModules();
        if (modules.empty()) return std::nullopt;
        return modules[0];
    }

    // ── QueryRegions: liệt kê vùng memory có thể scan ────
    struct MemRegion {
        uintptr_t base;
        size_t    size;
        DWORD     protect;
        DWORD     state;
        DWORD     type;
    };

    [[nodiscard]] std::vector<MemRegion>
    queryRegions(uintptr_t rangeBase, size_t rangeSize,
                 bool includeReadOnly, bool includeExecutable) const
    {
        std::vector<MemRegion> regions;
        uintptr_t addr    = rangeBase;
        uintptr_t end     = rangeBase + rangeSize;

        MEMORY_BASIC_INFORMATION mbi{};
        while (addr < end) {
            SIZE_T ret = VirtualQueryEx(handle_,
                reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi));
            if (ret == 0) break;

            if (mbi.State == MEM_COMMIT) {
                bool readable = false;
                DWORD p = mbi.Protect & ~(PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE);
                if (p == PAGE_READWRITE || p == PAGE_WRITECOPY)
                    readable = true;
                if (includeReadOnly  && p == PAGE_READONLY)
                    readable = true;
                if (includeExecutable &&
                    (p == PAGE_EXECUTE_READ || p == PAGE_EXECUTE_READWRITE))
                    readable = true;

                if (readable) {
                    MemRegion r;
                    r.base    = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
                    r.size    = mbi.RegionSize;
                    r.protect = mbi.Protect;
                    r.state   = mbi.State;
                    r.type    = mbi.Type;
                    // Clamp vào range
                    if (r.base + r.size > end) r.size = end - r.base;
                    regions.push_back(r);
                }
            }

            addr = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        }

        LOG_DEBUG("Found %zu readable regions in range [0x%llx, 0x%llx)",
                  regions.size(), rangeBase, rangeBase + rangeSize);
        return regions;
    }

    // ── Static factory: tìm PID theo tên process ─────────
    [[nodiscard]] static DWORD findPIDByName(const std::string& name) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE)
            return 0;

        std::string target = toLower(name);
        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);
        DWORD found = 0;

        if (Process32FirstW(snap, &pe)) {
            do {
                std::string pname = toLower(wideToUtf8(pe.szExeFile));
                if (pname == target) {
                    found = pe.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
        return found;
    }

private:
    HANDLE handle_ = nullptr;
    DWORD  pid_    = 0;

    static std::string wideToUtf8(const wchar_t* wstr) {
        if (!wstr || !*wstr) return {};
        int sz = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
        if (sz <= 0) return {};
        std::string result(sz - 1, '\0');
        WideCharToMultiByte(CP_UTF8, 0, wstr, -1, result.data(), sz, nullptr, nullptr);
        return result;
    }

    static std::string toLower(std::string s) {
        for (char& c : s) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
        return s;
    }
};

} // namespace FFlag
