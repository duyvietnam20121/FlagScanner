// ============================================================
//  FFlag Scanner/Dumper — Main Entry Point
//  File: main.cpp
//  CLI: parse args → configure → scan → export
// ============================================================
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <Windows.h>

#include "include/FlagTypes.hpp"
#include "include/Logger.hpp"
#include "include/ProcessHandle.hpp"
#include "include/PatternMatcher.hpp"
#include "include/FlagScanner.hpp"
#include "include/Exporter.hpp"

using namespace FFlag;

// ── Banner ────────────────────────────────────────────────
static void printBanner() {
    printf("\n");
    printf("  \033[36m╔══════════════════════════════════════════╗\033[0m\n");
    printf("  \033[36m║\033[0m  \033[1mFFlag Scanner / Dumper  v2.0\033[0m           \033[36m║\033[0m\n");
    printf("  \033[36m║\033[0m  Roblox FFlag Research Tool             \033[36m║\033[0m\n");
    printf("  \033[36m╚══════════════════════════════════════════╝\033[0m\n\n");
}

// ── Usage ─────────────────────────────────────────────────
static void printUsage(const char* exe) {
    printf("Usage: %s [options]\n\n", exe);
    printf("Options:\n");
    printf("  --pid <PID>         Target process ID (default: auto-find)\n");
    printf("  --process <name>    Process name (default: RobloxPlayerBeta.exe)\n");
    printf("  --module <name>     Module to scan (default: main module)\n");
    printf("  --outdir <path>     Output directory (default: .)\n");
    printf("  --no-json           Disable JSON export\n");
    printf("  --no-csv            Disable CSV export\n");
    printf("  --no-header         Disable C++ header export\n");
    printf("  --no-pattern        Disable signature/pattern scan\n");
    printf("  --no-strings        Disable string-based scan\n");
    printf("  --no-readonly       Skip PAGE_READONLY regions\n");
    printf("  --exec              Also scan executable regions\n");
    printf("  --chunk <MB>        Memory chunk size in MB (default: 4)\n");
    printf("  --verbose / -v      Enable debug logging\n");
    printf("  --logfile <path>    Also write log to file\n");
    printf("  --list-processes    List running processes and exit\n");
    printf("  --help / -h         Show this help\n\n");
    printf("Examples:\n");
    printf("  %s --verbose --outdir ./output\n", exe);
    printf("  %s --pid 12345 --no-csv\n", exe);
    printf("  %s --process RobloxPlayerBeta.exe --outdir C:\\dumps\n\n", exe);
}

// ── Arg helpers ───────────────────────────────────────────
static bool hasArg(const std::vector<std::string>& args, const std::string& flag) {
    return std::find(args.begin(), args.end(), flag) != args.end();
}
static std::string getArg(const std::vector<std::string>& args,
                          const std::string& flag,
                          const std::string& def = "") {
    auto it = std::find(args.begin(), args.end(), flag);
    if (it != args.end() && std::next(it) != args.end())
        return *std::next(it);
    return def;
}

// ── List processes ────────────────────────────────────────
static void listProcesses() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    printf("  %-8s  %-40s\n", "PID", "Name");
    printf("  %-8s  %-40s\n", "───────", "───────────────────────────────────────");

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            char name[MAX_PATH] = {};
            WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1,
                                name, sizeof(name), nullptr, nullptr);
            printf("  %-8lu  %s\n", pe.th32ProcessID, name);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
}

// ── Main ─────────────────────────────────────────────────
int main(int argc, char* argv[]) {
    printBanner();

    // Thu thập args
    std::vector<std::string> args(argv + 1, argv + argc);

    if (hasArg(args, "--help") || hasArg(args, "-h")) {
        printUsage(argv[0]);
        return 0;
    }
    if (hasArg(args, "--list-processes")) {
        listProcesses();
        return 0;
    }

    // ── Build ScanConfig từ CLI args ──────────────────────
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
        config.logFile    = getArg(args, "--logfile");
        config.logToFile  = true;
    }
    if (!getArg(args, "--chunk").empty())
        config.chunkSize = static_cast<size_t>(
            std::stoul(getArg(args, "--chunk")) * 1024 * 1024);

    config.exportJson       = !hasArg(args, "--no-json");
    config.exportCsv        = !hasArg(args, "--no-csv");
    config.exportCppHeader  = !hasArg(args, "--no-header");
    config.usePatternScan   = !hasArg(args, "--no-pattern");
    config.useStringSearch  = !hasArg(args, "--no-strings");
    config.scanReadOnly     = !hasArg(args, "--no-readonly");
    config.scanExecutable   =  hasArg(args, "--exec");
    config.verbose          =  hasArg(args, "--verbose") || hasArg(args, "-v");

    // ── Cấu hình logger ───────────────────────────────────
    Logger::instance().setVerbose(config.verbose);
    if (config.logToFile)
        Logger::instance().enableFileLog(config.logFile);

    // ── In config ─────────────────────────────────────────
    LOG_INFO("Configuration:");
    LOG_INFO("  Process   : %s%s",
             config.processName.c_str(),
             config.targetPID ? (" (PID=" + std::to_string(config.targetPID) + ")").c_str() : "");
    LOG_INFO("  Output    : %s", config.outputDir.c_str());
    LOG_INFO("  String scan   : %s", config.useStringSearch ? "yes" : "no");
    LOG_INFO("  Pattern scan  : %s", config.usePatternScan  ? "yes" : "no");
    LOG_INFO("  Export JSON   : %s", config.exportJson      ? "yes" : "no");
    LOG_INFO("  Export CSV    : %s", config.exportCsv       ? "yes" : "no");
    LOG_INFO("  Export Header : %s", config.exportCppHeader ? "yes" : "no");
    printf("\n");

    // ── Run scanner ───────────────────────────────────────
    FlagScanner scanner(config);
    DumpResult  result = scanner.scan();

    if (!result.success) {
        LOG_ERROR("Scan failed: %s", result.error.c_str());
        return 1;
    }

    // ── Export ────────────────────────────────────────────
    if (!Exporter::exportAll(result, config)) {
        LOG_WARN("Some exports failed (check log above)");
    }

    printf("\n");
    LOG_OK("Done! %zu FFlags dumped to: %s",
           result.flags.size(), config.outputDir.c_str());

    return 0;
}
