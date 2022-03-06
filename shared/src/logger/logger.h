#pragma once

// C++ Header File(s)
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

using time64_t = std::int64_t;

// Direct Interface for logging into log file or console using MACRO(s)
#define LOG_DEBUG(...) Logger::getInstance().debug(__VA_ARGS__)
#define LOG_INFO(...) Logger::getInstance().info(__VA_ARGS__)
#define LOG_ERROR(...) Logger::getInstance().error(__VA_ARGS__)
#define LOG_BUFFER(data, len) Logger::getInstance().buffer(data, len);

typedef enum LOG_STATUS {
  LOG_STATUS_DISABLED = 0,
  LOG_STATUS_ENABLED = 1
} LogStatus;

// enum for LOG_LEVEL
typedef enum LOG_LEVEL {
  LOG_LEVEL_DEBUG = 1,
  LOG_LEVEL_INFO = 2,
  LOG_LEVEL_ERROR = 3
} LogLevel;

// enum for LOG_TYPE
typedef enum LOG_TYPE {
  NO_LOG = 1,
  CONSOLE = 2,
  FILE_LOG = 3,
} LogType;

class Logger {
 public:
  static Logger& getInstance() noexcept;

  Logger(const Logger&) = delete;
  Logger& operator=(const Logger&) = delete;

  // Interfaces to control log levels
  void updateLogLevel(LogLevel logLevel);
  void enableLog();   // Enable all log levels
  void disableLog();  // Disable all log levels, except error and alarm

  // Interfaces to control log Types
  void updateLogType(LogType logType);

  void enableConsoleLogging();
  void enableFileLogging();

  // Interface for Debug log
  void debug(const char* fmt, ...) noexcept;
  void debug(std::string& text) noexcept;
  void debug(std::ostringstream& stream) noexcept;

  // Interface for Info Log
  void info(const char* fmt, ...) noexcept;
  void info(std::string& text) noexcept;
  void info(std::ostringstream& stream) noexcept;

  // Interface for Error Log
  int error(const char* fmt, ...) noexcept;
  int error(std::string& text) noexcept;
  int error(std::ostringstream& stream) noexcept;

  // Interface for Buffer Log
  void buffer(uint8_t* buff, size_t buff_size) noexcept;
  // void buffer(std::string& text) noexcept;
  // void buffer(std::ostringstream& stream) noexcept;

 protected:
  Logger();
  ~Logger();

  std::string getCurrentTime();
  int getLogConfig() noexcept;

 private:
  void logIntoFile(std::string& data);
  void logOnConsole(std::string& data);
  void log_log(std::ostream& out, LogLevel level, const char* text) noexcept;
  void writeConfigFile(std::string& filePath, std::string& sConfig) noexcept;

  void print_bytes(std::ostream& out, uint8_t* data, size_t dataLen,
                   bool format);

 private:
  std::ofstream m_File;
  std::fstream m_ConfigFile;
  char pbLog[MAX_PATH];
  char pbConfig[MAX_PATH];
  time64_t t64configTime;

  std::mutex m_Mutex;

  LogLevel m_LogLevel;
  LogType m_LogType;
  LogStatus m_LogStatus;
};

}  // namespace CieIDLogger
