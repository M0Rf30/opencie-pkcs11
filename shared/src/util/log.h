// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file log.h
 * @brief Logging facility for the CIE PKCS#11 library.
 *
 * Provides the CLog class for writing diagnostic and debug log messages
 * to file, including binary data dumps and function-level tracing.
 */

#pragma once

#ifdef _WIN32
// clang-format off
#include <winsock2.h>
#include <windows.h>
// clang-format on
#else
#include "../pcsc/scard_types.h"
#endif
#include <cstdint>
#include <cstdlib>
#include <string>

#ifndef OutputDebugString
#define OutputDebugString printf
#endif

/**
 * @brief Logging class for diagnostic output.
 *
 * Manages a log file and provides methods to write formatted text,
 * raw text, and binary data dumps. Supports per-module log configuration
 * and function-level call tracing.
 */
class CLog {
 public:
  unsigned int LogCount; /**< Number of log entries written. */
  bool Initialized;      /**< Whether the logger has been initialized. */
  bool Enabled;          /**< Whether logging is enabled. */
  bool FunctionLog;      /**< Whether function entry/exit logging is enabled. */
  bool LogParam;         /**< Whether parameter logging is enabled. */
  unsigned int ModuleNum;  /**< Module identifier number. */
  std::string logDir;      /**< Directory path for log files. */
  std::string logPath;     /**< Full path to the current log file. */
  std::string logName;     /**< Base name for the log. */
  std::string logFileName; /**< File name of the current log file. */
  std::string::iterator
      threadPos;          /**< Iterator position for thread info in log. */
  std::string logVersion; /**< Version string written to the log. */
  bool FirstLog;          /**< Whether this is the first log entry. */

  bool _stack_logged; /**< Whether the call stack has been logged. */

  /** @brief Default constructor. */
  CLog(void);

  /** @brief Destructor. Closes the log file if open. */
  ~CLog(void);

  /**
   * @brief Write a formatted log message.
   * @param format printf-style format string.
   * @return Status code (0 on success).
   */
  DWORD write(const char *format, ...);

  /**
   * @brief Write a formatted message without log metadata.
   * @param format printf-style format string.
   */
  void writePure(const char *format, ...);

  /**
   * @brief Write binary data as a hex dump.
   * @param data Pointer to the data buffer.
   * @param datalen Length of the data in bytes.
   */
  void writeBinData(uint8_t *data, size_t datalen);

  /** @brief Initialize the logger from configuration settings. */
  void init();

  /** @brief Dump any pending error information to the log. */
  void dumpErr();
};

/**
 * @brief Initialize the global logging system.
 * @param moduleName Name of the calling module.
 * @param iniFile Path to the INI configuration file.
 * @param version Version string for the module.
 */
void initLog(const char *moduleName, const char *iniFile, const char *version);
