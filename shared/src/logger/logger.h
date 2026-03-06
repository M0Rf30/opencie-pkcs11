// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file logger.h
 * @brief Thread-safe logging facility for the CIE PKCS#11 library.
 *
 * Provides a singleton Logger class supporting multiple log levels
 * (debug, info, error) and output targets (console, file). Log output
 * is controlled via a configuration file and can be toggled at runtime.
 */

#pragma once

#include <cstdint>
#include <fstream>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>

#ifndef MAX_PATH
#define MAX_PATH 1024
#endif

namespace CieIDLogger {

/** @brief 64-bit timestamp type for configuration file change tracking. */
using time64_t = std::int64_t;

/** @name Convenience logging macros
 *  Shorthand macros that forward to the Logger singleton.
 *  @{ */
#define LOG_DEBUG(...) Logger::getInstance().debug(__VA_ARGS__)
#define LOG_INFO(...) Logger::getInstance().info(__VA_ARGS__)
#define LOG_ERROR(...) Logger::getInstance().error(__VA_ARGS__)
#define LOG_BUFFER(data, len) Logger::getInstance().buffer(data, len);
/** @} */

/** @brief Whether logging is globally enabled or disabled. */
typedef enum LOG_STATUS {
  LOG_STATUS_DISABLED = 0, /**< Logging disabled. */
  LOG_STATUS_ENABLED = 1   /**< Logging enabled. */
} LogStatus;

/** @brief Minimum severity level for log output. */
typedef enum LOG_LEVEL {
  LOG_LEVEL_DEBUG = 1, /**< Verbose debug messages. */
  LOG_LEVEL_INFO = 2,  /**< Informational messages. */
  LOG_LEVEL_ERROR = 3  /**< Error messages only. */
} LogLevel;

/** @brief Log output destination type. */
typedef enum LOG_TYPE {
  NO_LOG = 1,   /**< No log output. */
  CONSOLE = 2,  /**< Log to standard output. */
  FILE_LOG = 3, /**< Log to a file on disk. */
} LogType;

/**
 * @class Logger
 * @brief Thread-safe singleton logger with configurable level and output
 * target.
 *
 * Provides debug, info, and error logging methods that can output to the
 * console or a log file. The singleton instance is obtained via getInstance().
 * Configuration can be loaded from a file and is automatically reloaded when
 * the configuration file changes.
 */
class Logger {
 public:
  /** @brief Get the singleton Logger instance. */
  static Logger& getInstance() noexcept;

  /** @brief Deleted copy constructor (singleton pattern). */
  Logger(const Logger&) = delete;
  /** @brief Deleted copy assignment operator (singleton pattern). */
  Logger& operator=(const Logger&) = delete;

  /** @brief Set the minimum log level threshold. */
  void updateLogLevel(LogLevel logLevel);
  /** @brief Enable all log levels. */
  void enableLog();
  /** @brief Disable all log levels except error. */
  void disableLog();

  /** @brief Set the log output destination type. */
  void updateLogType(LogType logType);

  /** @brief Enable logging to standard output. */
  void enableConsoleLogging();
  /** @brief Enable logging to a file on disk. */
  void enableFileLogging();

  /** @brief Log a debug message (printf-style format string). */
  void debug(const char* fmt, ...) noexcept;
  /** @brief Log a debug message (string reference). */
  void debug(std::string& text) noexcept;
  /** @brief Log a debug message (ostringstream). */
  void debug(std::ostringstream& stream) noexcept;

  /** @brief Log an informational message (printf-style format string). */
  void info(const char* fmt, ...) noexcept;
  /** @brief Log an informational message (string reference). */
  void info(std::string& text) noexcept;
  /** @brief Log an informational message (ostringstream). */
  void info(std::ostringstream& stream) noexcept;

  /** @brief Log an error message (printf-style format string).
   *  @return Always returns -1 for convenient error-return chaining. */
  int error(const char* fmt, ...) noexcept;
  /** @brief Log an error message (string reference). */
  int error(std::string& text) noexcept;
  /** @brief Log an error message (ostringstream). */
  int error(std::ostringstream& stream) noexcept;

  /** @brief Log a raw byte buffer as hex dump at debug level. */
  void buffer(uint8_t* buff, size_t buff_size) noexcept;
  // void buffer(std::string& text) noexcept;
  // void buffer(std::ostringstream& stream) noexcept;

 protected:
  Logger();  /**< @brief Protected constructor (use getInstance()). */
  ~Logger(); /**< @brief Protected destructor. */

  /** @brief Get the current local time as a formatted string. */
  std::string getCurrentTime();
  /** @brief Read and apply the logging configuration file.
   *  @return 0 on success, non-zero on failure. */
  int getLogConfig() noexcept;

 private:
  /** @brief Write a log entry to the log file. */
  void logIntoFile(std::string& data);
  /** @brief Write a log entry to the console (stdout). */
  void logOnConsole(std::string& data);
  /** @brief Core logging implementation that formats and writes a message. */
  void log_log(std::ostream& out, LogLevel level, const char* text) noexcept;
  /** @brief Write the current configuration to a file. */
  void writeConfigFile(std::string& filePath, std::string& sConfig) noexcept;

  /** @brief Format and print raw bytes as a hex dump. */
  void print_bytes(std::ostream& out, uint8_t* data, size_t dataLen,
                   bool format);

 private:
  std::ofstream m_File;      /**< Output log file stream. */
  std::fstream m_ConfigFile; /**< Configuration file stream. */
  char pbLog[MAX_PATH];      /**< Path to the log file. */
  char pbConfig[MAX_PATH];   /**< Path to the configuration file. */
  time64_t t64configTime;    /**< Last-modified timestamp of config file. */

  std::mutex m_Mutex; /**< Mutex guarding all logging operations. */

  LogLevel m_LogLevel;   /**< Current minimum log level. */
  LogType m_LogType;     /**< Current log output destination. */
  LogStatus m_LogStatus; /**< Whether logging is enabled or disabled. */
};

}  // namespace CieIDLogger
