# CMakeLists.txt – Android NDK build for Ghidra's native decompiler library.
#
# This file compiles the Ghidra decompiler (written in C++11) into a shared
# library (libdecompiler.so) for the arm64-v8a and armeabi-v7a ABIs.
#
# Usage (invoked automatically by Gradle via the 'externalNativeBuild' block
# in build.gradle):
#
#   cmake -DCMAKE_TOOLCHAIN_FILE=$NDK/build/cmake/android.toolchain.cmake \
#         -DANDROID_ABI=arm64-v8a \
#         -DANDROID_PLATFORM=android-26 \
#         -DCMAKE_BUILD_TYPE=Release \
#         ..
#
# Prerequisites:
#   - Android NDK r25 or later
#   - The Ghidra decompiler C++ sources must be present under
#     ../../Ghidra/Features/Decompiler/src/decompile/cpp relative to this file.

cmake_minimum_required(VERSION 3.22)
project(decompiler CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# -----------------------------------------------------------------------
# Source path (relative to this CMakeLists.txt which lives in
# GhidraAndroid/src/main/cpp/)
# -----------------------------------------------------------------------
set(DECOMPILER_SRC
    "${CMAKE_CURRENT_SOURCE_DIR}/../../../../../Ghidra/Features/Decompiler/src/decompile/cpp")

# -----------------------------------------------------------------------
# Collect source files
# -----------------------------------------------------------------------
file(GLOB DECOMPILER_SOURCES "${DECOMPILER_SRC}/*.cc")

# Exclude desktop-only entry points that pull in stdin/stdout main loops
# or depend on POSIX features that are not required for the library.
list(FILTER DECOMPILER_SOURCES EXCLUDE REGEX ".*bfd_arch\\.cc$")
list(FILTER DECOMPILER_SOURCES EXCLUDE REGEX ".*raw_arch\\.cc$")
list(FILTER DECOMPILER_SOURCES EXCLUDE REGEX ".*sleigh_arch\\.cc$")

# JNI bridge source (provides the Java_ghidra_* native method signatures
# that Ghidra's Java layer expects when it calls System.loadLibrary).
set(JNI_BRIDGE_SRC "${CMAKE_CURRENT_SOURCE_DIR}/ghidra_jni_bridge.cpp")

# -----------------------------------------------------------------------
# Shared library target
# -----------------------------------------------------------------------
add_library(
    decompiler
    SHARED
    ${DECOMPILER_SOURCES}
    ${JNI_BRIDGE_SRC}
)

target_include_directories(decompiler PRIVATE
    "${DECOMPILER_SRC}"
    "${CMAKE_CURRENT_SOURCE_DIR}"
)

# Android provides zlib as part of the platform.
find_library(ZLIB_LIB z)

# Link against Android log library for __android_log_print.
find_library(LOG_LIB log)

target_link_libraries(decompiler
    ${ZLIB_LIB}
    ${LOG_LIB}
)

# -----------------------------------------------------------------------
# Compiler flags
# -----------------------------------------------------------------------
target_compile_options(decompiler PRIVATE
    -O2
    -Wall
    -Wno-sign-compare
    -fvisibility=hidden        # only explicitly exported symbols are visible
    -DGIT_HASH=\"unknown\"     # suppress missing-macro warnings in ghidra source
)
