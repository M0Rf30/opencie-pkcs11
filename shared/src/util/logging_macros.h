// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

#pragma once

#include <cstdarg>
#include <cstdio>
#include <ctime>

#ifdef __ANDROID__
#include <android/log.h>
#define CIE_ANDROID_LOG_TAG "CIE-LIB"
#endif

namespace cie_logging {
// Simple printf-based logging that avoids spdlog/fmt conflicts entirely
inline void printf_fallback_log(int level, const char* /* module */,
                                const char* format, ...) {
  char buffer[2048];
  va_list args;
  va_start(args, format);
  vsnprintf(buffer, sizeof(buffer), format, args);
  va_end(args);

#ifdef __ANDROID__
  android_LogPriority prio;
  switch (level) {
    case 0:
      return;
    case 1:
      prio = ANDROID_LOG_ERROR;
      break;
    case 2:
      prio = ANDROID_LOG_WARN;
      break;
    case 3:
      prio = ANDROID_LOG_INFO;
      break;
    case 4:
      prio = ANDROID_LOG_DEBUG;
      break;
    default:
      prio = ANDROID_LOG_VERBOSE;
      break;
  }
  __android_log_print(prio, CIE_ANDROID_LOG_TAG, "%s", buffer);
#else
  const char* level_str = "INFO";
  switch (level) {
    case 0:
      return;
    case 1:
      level_str = "ERROR";
      break;
    case 2:
      level_str = "WARN";
      break;
    case 3:
      level_str = "INFO";
      break;
    case 4:
      level_str = "DEBUG";
      break;
  }

  // Get current timestamp
  time_t rawtime;
  struct tm* timeinfo;
  char timestamp[32];
  time(&rawtime);
  timeinfo = localtime(&rawtime);
  strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", timeinfo);

  // Print the complete log message
  printf("[%s] [%s] [%s] %s\n", timestamp, "cie", level_str, buffer);
  fflush(stdout);
#endif
}

// Level constants for consistency
constexpr int DEBUG_LEVEL = 4;
constexpr int ERROR_LEVEL = 1;
constexpr int INFO_LEVEL = 3;
constexpr int WARN_LEVEL = 2;
constexpr int OFF_LEVEL = 0;

// Global log level setting
static int current_log_level = DEBUG_LEVEL;

inline void set_log_level(int level) { current_log_level = level; }

inline bool should_log(int level) {
  return level <= current_log_level && level != OFF_LEVEL;
}
}  // namespace cie_logging

// Legacy logging macros that extract format from old tuple format
// OLD FORMAT: LOG_MSG((0, "module", "format string", args...))

#define LOG_DBG_IMPL(level, module, format, ...)                         \
  do {                                                                   \
    if (cie_logging::should_log(cie_logging::DEBUG_LEVEL)) {             \
      cie_logging::printf_fallback_log(cie_logging::DEBUG_LEVEL, module, \
                                       format, ##__VA_ARGS__);           \
    }                                                                    \
  } while (0)

#define LOG_ERR_IMPL(level, module, format, ...)                         \
  do {                                                                   \
    if (cie_logging::should_log(cie_logging::ERROR_LEVEL)) {             \
      cie_logging::printf_fallback_log(cie_logging::ERROR_LEVEL, module, \
                                       format, ##__VA_ARGS__);           \
    }                                                                    \
  } while (0)

#define LOG_MSG_IMPL(level, module, format, ...)                        \
  do {                                                                  \
    if (cie_logging::should_log(cie_logging::INFO_LEVEL)) {             \
      cie_logging::printf_fallback_log(cie_logging::INFO_LEVEL, module, \
                                       format, ##__VA_ARGS__);          \
    }                                                                   \
  } while (0)

#define LOG_WARN_IMPL(level, module, format, ...)                       \
  do {                                                                  \
    if (cie_logging::should_log(cie_logging::WARN_LEVEL)) {             \
      cie_logging::printf_fallback_log(cie_logging::WARN_LEVEL, module, \
                                       format, ##__VA_ARGS__);          \
    }                                                                   \
  } while (0)

#define LOG_DBG(args) LOG_DBG_IMPL args
#define LOG_ERR(args) LOG_ERR_IMPL args
#define LOG_MSG(args) LOG_MSG_IMPL args
#define LOG_WARN(args) LOG_WARN_IMPL args

// File and level configuration macros
#define SET_LOG_FILE(filepath)                            \
  do {                                                    \
    /* File logging not implemented in printf fallback */ \
  } while (0)

#define SET_LOG_LEVEL(level)             \
  do {                                   \
    cie_logging::set_log_level((level)); \
  } while (0)
