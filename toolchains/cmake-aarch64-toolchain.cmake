# CMake toolchain file used by Meson when configuring CMake-based subprojects
# (e.g. libpodofo) for an aarch64 Linux cross-build.
#
# Referenced from cross-aarch64.ini via the `cmake_toolchain_file` property.

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

set(CMAKE_C_COMPILER   /usr/bin/aarch64-linux-gnu-gcc)
set(CMAKE_CXX_COMPILER /usr/bin/aarch64-linux-gnu-g++)
set(CMAKE_AR           /usr/bin/aarch64-linux-gnu-ar)
set(CMAKE_STRIP        /usr/bin/aarch64-linux-gnu-strip)

# Look for libraries in the aarch64 multiarch directories.
set(CMAKE_FIND_ROOT_PATH /usr/aarch64-linux-gnu /usr/lib/aarch64-linux-gnu)

# On Debian/Ubuntu multiarch, headers (e.g. zlib.h) live in the shared
# /usr/include while libs are arch-specific in /usr/lib/aarch64-linux-gnu.
# Restrict library lookups to the aarch64 paths but allow headers from the
# host filesystem too (BOTH), otherwise find_package(ZLIB) etc. fail.
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE BOTH)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE BOTH)
