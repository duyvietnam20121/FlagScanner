cmake_minimum_required(VERSION 3.20)
project(FlagScanner LANGUAGES CXX)

# ── C++20 required ──────────────────────────────────────────
set(CMAKE_CXX_STANDARD          20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS        OFF)

# ── Compiler flags ─────────────────────────────────────────
if(MSVC)
    add_compile_options(
        /W4           # Warning level 4
        /WX           # Warnings as errors
        /permissive-  # Strict conformance
        /Zc:__cplusplus
        /utf-8
        /O2
    )
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -O2)
endif()

# ── Target ─────────────────────────────────────────────────
add_executable(FlagScanner
    main.cpp
)

target_include_directories(FlagScanner PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# ── Windows-specific ───────────────────────────────────────
if(WIN32)
    target_link_libraries(FlagScanner PRIVATE
        psapi       # GetModuleInformation
    )
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        target_compile_definitions(FlagScanner PRIVATE _WIN64)
    endif()
endif()

# ── Output directory ───────────────────────────────────────
set_target_properties(FlagScanner PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# ── SUBSYSTEM:CONSOLE — bắt buộc hiện cửa sổ terminal ─────
# Thiếu dòng này → double-click exe không thấy gì cả vì
# MSVC mặc định link với WINDOWS subsystem (no console window)
if(MSVC)
    set_target_properties(FlagScanner PROPERTIES
        LINK_FLAGS "/SUBSYSTEM:CONSOLE"
    )
elseif(MINGW)
    target_link_options(FlagScanner PRIVATE -mconsole)
endif()

message(STATUS "FlagScanner configured: C++${CMAKE_CXX_STANDARD}, MSVC=${MSVC}")