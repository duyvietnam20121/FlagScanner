cmake_minimum_required(VERSION 3.20)
project(FlagScanner LANGUAGES CXX)

# ── C++20 required (std::filesystem, designated initializers) ──
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
        /O2           # Optimise release builds
    )
    # Tắt warning về POSIX deprecation
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -O2)
endif()

# ── Target ─────────────────────────────────────────────────
add_executable(FlagScanner
    main.cpp
    # Headers only — no .cpp needed (header-only library)
)

target_include_directories(FlagScanner PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# ── Windows-specific libraries ─────────────────────────────
if(WIN32)
    target_link_libraries(FlagScanner PRIVATE
        psapi       # GetModuleInformation
    )
    # 64-bit target
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        target_compile_definitions(FlagScanner PRIVATE _WIN64)
    endif()
endif()

# ── Output config ──────────────────────────────────────────
set_target_properties(FlagScanner PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

message(STATUS "FlagScanner configured: C++${CMAKE_CXX_STANDARD}, "
               "MSVC=${MSVC}, x64=${CMAKE_SIZEOF_VOID_P}")
