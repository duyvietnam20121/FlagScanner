#pragma once
#include <string>
#include <string_view>
#include <fstream>
#include <mutex>
#include <memory>
#include <cstdio>
#include <ctime>
#include <sstream>

// ============================================================
//  FFlag Scanner/Dumper — Logger
//  File: Logger.hpp
//  Thread-safe logger với level, color (ANSI), optional file
// ============================================================

namespace FFlag {

// ────────────────────────────────────────────────────────────
//  Enum: LogLevel
// ────────────────────────────────────────────────────────────
enum class LogLevel : uint8_t {
    Debug   = 0,
    Info    = 1,
    Warn    = 2,
    Error   = 3,
    Success = 4,
    Silent  = 5,   // tắt hoàn toàn
};

// ────────────────────────────────────────────────────────────
//  Class: Logger — singleton, thread-safe
// ────────────────────────────────────────────────────────────
class Logger {
public:
    // Lấy instance singleton
    static Logger& instance() {
        static Logger inst;
        return inst;
    }

    // Cấu hình
    void setLevel(LogLevel lvl)          { minLevel_ = lvl; }
    void setVerbose(bool v)              { minLevel_ = v ? LogLevel::Debug : LogLevel::Info; }
    void enableFileLog(const std::string& path) {
        std::lock_guard<std::mutex> lock(mu_);
        fileStream_.open(path, std::ios::app);
    }
    void disableFileLog() {
        std::lock_guard<std::mutex> lock(mu_);
        if (fileStream_.is_open()) fileStream_.close();
    }
    void enableColors(bool v)            { useColors_ = v; }

    // ── Core log methods ──────────────────────────────────
    void debug(std::string_view msg)   { log(LogLevel::Debug,   "[DBG] ", "\033[90m",  msg); }
    void info(std::string_view msg)    { log(LogLevel::Info,    "[INF] ", "\033[36m",  msg); }
    void warn(std::string_view msg)    { log(LogLevel::Warn,    "[WRN] ", "\033[33m",  msg); }
    void error(std::string_view msg)   { log(LogLevel::Error,   "[ERR] ", "\033[31m",  msg); }
    void success(std::string_view msg) { log(LogLevel::Success, "[OK]  ", "\033[32m",  msg); }

    // ── Printf-style convenience ──────────────────────────
    template<typename... Args>
    void debugf(const char* fmt, Args&&... args)   { logf(LogLevel::Debug,   "[DBG] ", "\033[90m", fmt, std::forward<Args>(args)...); }
    template<typename... Args>
    void infof(const char* fmt, Args&&... args)    { logf(LogLevel::Info,    "[INF] ", "\033[36m", fmt, std::forward<Args>(args)...); }
    template<typename... Args>
    void warnf(const char* fmt, Args&&... args)    { logf(LogLevel::Warn,    "[WRN] ", "\033[33m", fmt, std::forward<Args>(args)...); }
    template<typename... Args>
    void errorf(const char* fmt, Args&&... args)   { logf(LogLevel::Error,   "[ERR] ", "\033[31m", fmt, std::forward<Args>(args)...); }
    template<typename... Args>
    void successf(const char* fmt, Args&&... args) { logf(LogLevel::Success, "[OK]  ", "\033[32m", fmt, std::forward<Args>(args)...); }

    // Progress bar đơn giản
    void progress(size_t current, size_t total, std::string_view label = "") {
        if (minLevel_ > LogLevel::Info) return;
        double pct = (total > 0) ? (100.0 * current / total) : 0.0;
        int filled = static_cast<int>(pct / 5.0);  // 20 ký tự bar
        std::string bar(20, ' ');
        for (int i = 0; i < filled && i < 20; ++i) bar[i] = '#';
        std::lock_guard<std::mutex> lock(mu_);
        // Dùng \r để overwrite dòng hiện tại
        fprintf(stdout, "\r\033[36m[%s] [%-20s] %.1f%%\033[0m",
            label.empty() ? "SCAN" : label.data(), bar.c_str(), pct);
        fflush(stdout);
        if (current >= total) fprintf(stdout, "\n");
    }

private:
    LogLevel    minLevel_  = LogLevel::Info;
    bool        useColors_ = true;
    std::mutex  mu_;
    std::ofstream fileStream_;

    Logger() {
        // Bật ANSI colors trên Windows 10+
#ifdef _WIN32
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hOut != INVALID_HANDLE_VALUE) {
            DWORD dwMode = 0;
            if (GetConsoleMode(hOut, &dwMode)) {
                SetConsoleMode(hOut, dwMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
            }
        }
#endif
    }

    // Lấy timestamp "HH:MM:SS.mmm"
    static std::string timestamp() {
        SYSTEMTIME st;
        GetLocalTime(&st);
        char buf[24];
        snprintf(buf, sizeof(buf), "%02d:%02d:%02d.%03d",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
        return buf;
    }

    void log(LogLevel lvl, const char* prefix, const char* color, std::string_view msg) {
        if (lvl < minLevel_) return;
        std::lock_guard<std::mutex> lock(mu_);

        std::string ts = timestamp();
        if (useColors_) {
            fprintf(stdout, "%s%s %s %.*s\033[0m\n",
                color, ts.c_str(), prefix,
                static_cast<int>(msg.size()), msg.data());
        } else {
            fprintf(stdout, "%s %s %.*s\n",
                ts.c_str(), prefix,
                static_cast<int>(msg.size()), msg.data());
        }

        if (fileStream_.is_open()) {
            fileStream_ << ts << ' ' << prefix
                        << std::string(msg) << '\n';
        }
    }

    template<typename... Args>
    void logf(LogLevel lvl, const char* prefix, const char* color,
              const char* fmt, Args&&... args) {
        if (lvl < minLevel_) return;
        // Format string trước
        char buf[2048];
        snprintf(buf, sizeof(buf), fmt, std::forward<Args>(args)...);
        log(lvl, prefix, color, buf);
    }
};

// ── Macro tiện lợi ───────────────────────────────────────────
#define LOG_DEBUG(...)   FFlag::Logger::instance().debugf(__VA_ARGS__)
#define LOG_INFO(...)    FFlag::Logger::instance().infof(__VA_ARGS__)
#define LOG_WARN(...)    FFlag::Logger::instance().warnf(__VA_ARGS__)
#define LOG_ERROR(...)   FFlag::Logger::instance().errorf(__VA_ARGS__)
#define LOG_OK(...)      FFlag::Logger::instance().successf(__VA_ARGS__)

} // namespace FFlag
