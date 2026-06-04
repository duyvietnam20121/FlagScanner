// ============================================================
//  FFlag Scanner/Dumper — Main Entry Point  v2.1
//  File: main.cpp
// ============================================================
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <conio.h>
#include <Windows.h>

#include "include/FlagTypes.hpp"
#include "include/Logger.hpp"
#include "include/ProcessHandle.hpp"
#include "include/PatternMatcher.hpp"
#include "include/FlagListWalker.hpp"
#include "include/FlagScanner.hpp"
#include "include/Exporter.hpp"

using namespace FFlag;

// ─────────────────────────────────────────────────────────────
static void ensureConsole() {
    if (AttachConsole(ATTACH_PARENT_PROCESS)) {
        FILE* fp = nullptr;
        freopen_s(&fp, "CONOUT$", "w", stdout);
        freopen_s(&fp, "CONOUT$", "w", stderr);
        freopen_s(&fp, "CONIN$",  "r", stdin);
        return;
    }
    if (AllocConsole()) {
        FILE* fp = nullptr;
        freopen_s(&fp, "CONOUT$", "w", stdout);
        freopen_s(&fp, "CONOUT$", "w", stderr);
        freopen_s(&fp, "CONIN$",  "r", stdin);
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD mode = 0;
        if (GetConsoleMode(hOut, &mode))
            SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        SetConsoleTitleA("FFlag Scanner v2.1");
    }
}

// ─────────────────────────────────────────────────────────────
static void printBanner() {
    printf("\n");
    printf("  \033[36m╔══════════════════════════════════════════════╗\033[0m\n");
    printf("  \033[36m║\033[0m  \033[1mFFlag Scanner / Dumper  v2.1\033[0m             \033[36m║\033[0m\n");
    printf("  \033[36m║\033[0m  \033[90mRoblox FFlag Research Tool\033[0m               \033[36m║\033[0m\n");
    printf("  \033[36m╚══════════════════════════════════════════════╝\033[0m\n\n");
}

// ─────────────────────────────────────────────────────────────
static void printUsage(const char* exe) {
    printf("Usage: %s [options]\n\n", exe);
    printf("\033[33mScan options:\033[0m\n");
    printf("  --pid <PID>           Target process ID\n");
    printf("  --process <name>      Process name (default: RobloxPlayerBeta.exe)\n");
    printf("  --module <name>       Module to scan (default: main module)\n");
    printf("  --rva <hex>           FFlagList RVA (default: 0x8100E00)\n");
    printf("  --walker-only         Chỉ dùng FFlagList walk, không fallback\n");
    printf("  --scan-only           Bỏ qua FFlagList walk, dùng string scan\n\n");

    printf("\033[33mProbe / debug:\033[0m\n");
    printf("  --probe <hex>         Probe FlagObject tại địa chỉ (Cheat Engine addr)\n");
    printf("  --list-processes      Liệt kê process đang chạy\n\n");

    printf("\033[33mExport options:\033[0m\n");
    printf("  --outdir <path>       Output directory (default: .)\n");
    printf("  --no-json             Tắt JSON export\n");
    printf("  --no-csv              Tắt CSV export\n");
    printf("  --no-header           Tắt C++ header export\n\n");

    printf("\033[33mOther:\033[0m\n");
    printf("  --verbose / -v        Debug logging\n");
    printf("  --logfile <path>      Ghi log ra file\n");
    printf("  --help / -h           Hiện help này\n\n");

    printf("\033[33mExamples:\033[0m\n");
    printf("  %s\n", exe);
    printf("  %s --rva 0x8200F00 --outdir ./output\n", exe);
    printf("  %s --probe 0x1F4AB3C0 --pid 12345\n", exe);
    printf("  %s --scan-only --verbose\n\n", exe);

    printf("\033[90mTip: Khi Roblox update, dùng --probe <addr> để tìm offset mới.\033[0m\n");
    printf("\033[90m     Lấy addr bằng Cheat Engine: scan string \"FFlagMyFeature\",\033[0m\n");
    printf("\033[90m     xem ai reference tới nó → đó là FlagObject.\033[0m\n\n");
}

// ─────────────────────────────────────────────────────────────
static bool hasArg(const std::vector<std::string>& args, const std::string& f) {
    return std::find(args.begin(), args.end(), f) != args.end();
}
static std::string getArg(const std::vector<std::string>& args,
                           const std::string& f, const std::string& def = "") {
    auto it = std::find(args.begin(), args.end(), f);
    if (it != args.end() && std::next(it) != args.end()) return *std::next(it);
    return def;
}
static uintptr_t parseHex(const std::string& s) {
    try { return std::stoull(s, nullptr, 16); }
    catch (...) { return 0; }
}

// ─────────────────────────────────────────────────────────────
static void listProcesses() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    printf("  \033[33m%-8s  %-45s\033[0m\n", "PID", "Name");
    printf("  %-8s  %-45s\n", "────────", "─────────────────────────────────────────────");
    PROCESSENTRY32W pe{ sizeof(pe) };
    if (Process32FirstW(snap, &pe)) {
        do {
            char name[MAX_PATH]{};
            WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, name, sizeof(name), nullptr, nullptr);
            // Highlight Roblox process
            bool isRoblox = strstr(name, "Roblox") || strstr(name, "roblox");
            if (isRoblox) printf("  \033[36m%-8lu  %s\033[0m\n", pe.th32ProcessID, name);
            else          printf("  %-8lu  %s\n",              pe.th32ProcessID, name);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
}

// ─────────────────────────────────────────────────────────────
static void pauseIfNeeded() {
    if (GetConsoleWindow() != nullptr) {
        printf("\n  \033[90mPress any key to exit...\033[0m\n");
        (void)_getch();
    }
}

// ─────────────────────────────────────────────────────────────
int main(int argc, char* argv[]) {
    ensureConsole();
    printBanner();

    std::vector<std::string> args(argv + 1, argv + argc);

    if (hasArg(args, "--help") || hasArg(args, "-h")) {
        printUsage(argv[0]);
        pauseIfNeeded();
        return 0;
    }
    if (hasArg(args, "--list-processes")) {
        listProcesses();
        pauseIfNeeded();
        return 0;
    }

    // ── Build ScanConfig ──────────────────────────────────
    ScanConfig config;
    if (!getArg(args, "--pid").empty())
        config.targetPID = static_cast<DWORD>(std::stoul(getArg(args, "--pid")));
    if (!getArg(args, "--process").empty())
        config.processName = getArg(args, "--process");
    if (!getArg(args, "--module").empty())
        config.moduleName = getArg(args, "--module");
    if (!getArg(args, "--outdir").empty())
        config.outputDir = getArg(args, "--outdir");
    if (!getArg(args, "--logfile").empty()) {
        config.logFile   = getArg(args, "--logfile");
        config.logToFile = true;
    }
    config.exportJson      = !hasArg(args, "--no-json");
    config.exportCsv       = !hasArg(args, "--no-csv");
    config.exportCppHeader = !hasArg(args, "--no-header");
    config.verbose         =  hasArg(args, "--verbose") || hasArg(args, "-v");
    config.useStringSearch = !hasArg(args, "--walker-only");
    config.usePatternScan  = !hasArg(args, "--walker-only");

    // ── Build WalkerConfig ────────────────────────────────
    WalkerConfig walkerCfg;
    walkerCfg.enabled      = !hasArg(args, "--scan-only");
    walkerCfg.fallbackScan = !hasArg(args, "--walker-only");

    // Override FFlagListRVA nếu user cung cấp
    if (!getArg(args, "--rva").empty()) {
        uintptr_t rva = parseHex(getArg(args, "--rva"));
        if (rva == 0) {
            LOG_ERROR("Invalid --rva value: %s", getArg(args, "--rva").c_str());
            pauseIfNeeded();
            return 1;
        }
        walkerCfg.offsets.FFlagListRVA = rva;
        LOG_INFO("Using custom FFlagListRVA = 0x%llx", rva);
    }

    // ── Logger setup ──────────────────────────────────────
    Logger::instance().setVerbose(config.verbose);
    if (config.logToFile)
        Logger::instance().enableFileLog(config.logFile);

    // ── Print config ──────────────────────────────────────
    LOG_INFO("Process     : %s", config.processName.c_str());
    LOG_INFO("FFlagList   : RVA 0x%llx", walkerCfg.offsets.FFlagListRVA);
    LOG_INFO("Method      : %s",
             !walkerCfg.enabled  ? "string scan only" :
             !walkerCfg.fallbackScan ? "walker only" :
             "walker + fallback");
    LOG_INFO("Output      : %s", config.outputDir.c_str());
    printf("\n");

    // ── PROBE MODE ────────────────────────────────────────
    if (!getArg(args, "--probe").empty()) {
        uintptr_t addr = parseHex(getArg(args, "--probe"));
        if (addr == 0) {
            LOG_ERROR("Invalid --probe address: %s", getArg(args, "--probe").c_str());
            pauseIfNeeded();
            return 1;
        }
        FlagScanner scanner(config, walkerCfg);
        scanner.probe(addr);
        pauseIfNeeded();
        return 0;
    }

    // ── SCAN ──────────────────────────────────────────────
    FlagScanner scanner(config, walkerCfg);
    DumpResult  result = scanner.scan();

    if (!result.success) {
        LOG_ERROR("Scan failed: %s", result.error.c_str());

        // Gợi ý cụ thể
        printf("\n  \033[33mGợi ý:\033[0m\n");
        printf("  1. Chạy lại với --verbose để xem chi tiết\n");
        printf("  2. Dùng Cheat Engine scan string \"FFlagMyFeature\"\n");
        printf("     → xem xref → lấy địa chỉ FlagObject\n");
        printf("  3. Chạy:  %s --probe <addr>  để tự detect offset\n", argv[0]);
        printf("  4. Sau đó: %s --rva <new_rva>\n\n", argv[0]);

        pauseIfNeeded();
        return 1;
    }

    // ── EXPORT ────────────────────────────────────────────
    if (!Exporter::exportAll(result, config))
        LOG_WARN("Một số export thất bại");

    printf("\n");
    LOG_OK("Done!  \033[1m%zu flags\033[0m  →  %s",
           result.flags.size(), config.outputDir.c_str());

    pauseIfNeeded();
    return 0;
}