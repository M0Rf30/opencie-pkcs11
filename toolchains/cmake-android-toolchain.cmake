# CMake toolchain for cross-compiling the libpodofo Meson subproject to Android.
#
# Thin wrapper around the NDK's official toolchain file
# ($ANDROID_NDK_ROOT/build/cmake/android.toolchain.cmake). The ABI, platform,
# and NDK path are taken from environment variables so the same file serves
# both arm64 and x86_64 builds.
#
# Required environment (set by the workflow / local invocation):
#   ANDROID_NDK_ROOT  Absolute path to the NDK installation.
#   ANDROID_ABI       arm64-v8a | x86_64 | ...
#   ANDROID_PLATFORM  android-24 (or similar). Must match the api level used
#                     in the matching cross-android-*.ini cross file.
#
# This file is referenced from toolchains/cross-android-*.ini via
# cmake_toolchain_file. Meson 1.x requires the path to be absolute; the cross
# file uses a @SOURCE_ROOT@ placeholder that is substituted with the absolute
# repository path before `meson setup` runs.

if(NOT DEFINED ANDROID_NDK AND DEFINED ENV{ANDROID_NDK_ROOT})
  set(ANDROID_NDK "$ENV{ANDROID_NDK_ROOT}" CACHE PATH "Android NDK path")
endif()
if(NOT DEFINED ANDROID_ABI AND DEFINED ENV{ANDROID_ABI})
  set(ANDROID_ABI "$ENV{ANDROID_ABI}" CACHE STRING "Android ABI")
endif()
if(NOT DEFINED ANDROID_PLATFORM AND DEFINED ENV{ANDROID_PLATFORM})
  set(ANDROID_PLATFORM "$ENV{ANDROID_PLATFORM}" CACHE STRING "Android platform")
endif()

if(NOT ANDROID_NDK)
  message(FATAL_ERROR
    "ANDROID_NDK is not set. Export ANDROID_NDK_ROOT before running meson "
    "setup, or pass -DANDROID_NDK=<path> via cmake.")
endif()

include("${ANDROID_NDK}/build/cmake/android.toolchain.cmake")

# Make vcpkg-installed dependencies (OpenSSL, freetype, libpng, libxml2, ...)
# discoverable by find_package() inside the libpodofo CMake subproject.
#
# The NDK toolchain sets CMAKE_FIND_ROOT_PATH to the NDK sysroot and
# CMAKE_FIND_ROOT_PATH_MODE_PACKAGE=ONLY, which blocks find_package() from
# looking outside the sysroot. We append the vcpkg install tree to
# CMAKE_FIND_ROOT_PATH (so it's still subject to the cross sysroot rules) and
# relax PACKAGE / INCLUDE search modes to BOTH, while keeping LIBRARY=ONLY so
# host libraries can never leak in.
if(DEFINED ENV{VCPKG_INSTALLED_DIR} AND DEFINED ENV{VCPKG_TARGET_TRIPLET})
  set(_vcpkg_root "$ENV{VCPKG_INSTALLED_DIR}/$ENV{VCPKG_TARGET_TRIPLET}")
  list(APPEND CMAKE_FIND_ROOT_PATH "${_vcpkg_root}")
  list(APPEND CMAKE_PREFIX_PATH "${_vcpkg_root}")
  set(OPENSSL_ROOT_DIR "${_vcpkg_root}" CACHE PATH "vcpkg OpenSSL root")
  set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE BOTH)
  set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE BOTH)

  # Hard-pin find_package() result variables for libpodofo's deps. Without
  # this, CMake's FindLibXml2 / FindFreetype / FindPNG modules can resolve
  # find_library() to host-side libs the NDK toolchain accidentally exposes
  # (e.g. NDK r27 ships an x86_64 libxml2.so under
  # toolchains/llvm/prebuilt/linux-x86_64/lib/ for clang's own use, which
  # leaks into target links and fails arm64 with `incompatible with
  # aarch64linux`). Bypass discovery entirely by pre-setting the cache vars.
  if(EXISTS "${_vcpkg_root}/lib/libxml2.a")
    set(LIBXML2_LIBRARY     "${_vcpkg_root}/lib/libxml2.a" CACHE FILEPATH "" FORCE)
    set(LIBXML2_INCLUDE_DIR "${_vcpkg_root}/include"       CACHE PATH     "" FORCE)
  endif()
  if(EXISTS "${_vcpkg_root}/lib/libfreetype.a")
    set(FREETYPE_LIBRARY      "${_vcpkg_root}/lib/libfreetype.a" CACHE FILEPATH "" FORCE)
    set(FREETYPE_INCLUDE_DIRS "${_vcpkg_root}/include/freetype2" CACHE STRING   "" FORCE)
  endif()
  if(EXISTS "${_vcpkg_root}/lib/libpng.a")
    set(PNG_LIBRARY         "${_vcpkg_root}/lib/libpng.a" CACHE FILEPATH "" FORCE)
    set(PNG_PNG_INCLUDE_DIR "${_vcpkg_root}/include"      CACHE PATH     "" FORCE)
  endif()
endif()
