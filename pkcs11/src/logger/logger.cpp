// SPDX-License-Identifier: LGPL-3.0-or-later
#include "logger/logger.h"

#include <sys/stat.h>

#include <climits>
#include <cstdarg>

#ifdef _WIN32
#include <shlwapi.h>
#include <windows.h>
#define stat _stat
#elif defined(__ANDROID__)
#include <android/log.h>
#define CIE_LOG_TAG "CIE-LIB"
#else
#include <sys/time.h>
#include <unistd.h>
#endif

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <iostream>

namespace CieIDLogger {

inline bool config_exists(const std::string& name) {
  std::ifstream f(name.c_str());
  return f.good();
}

// Folder path string
// char szLogDir[PATH_MAX];

static const char* level_strings[] = {"", "[DEBUG]", "[INFO]", "[ERROR]"};

Logger::Logger() {
  t64configTime = static_cast<time64_t>(0);

#ifdef __ANDROID__
  m_LogLevel = LOG_LEVEL_DEBUG;
  m_LogStatus = LOG_STATUS_ENABLED;
  m_LogType = CONSOLE;
  return;
#elif defined(_WIN32)
  SYSTEMTIME stTime;
  char* buf = nullptr;
  size_t sz = 0;

  GetLocalTime(&stTime);
#if defined(_MSC_VER)
  _dupenv_s(&buf, &sz, "PROGRAMDATA");
#else
  if (const char* _pd = getenv("PROGRAMDATA")) {
    sz = strlen(_pd) + 1;
    buf = static_cast<char*>(malloc(sz));
    if (buf) memcpy(buf, _pd, sz);
  }
#endif
  sprintf_s(pbLog, sizeof(pbLog), "%s/CIEPKI/CIEPKI_%04d-%02d-%02d.log",
            buf ? buf : "C:\\ProgramData", stTime.wYear, stTime.wMonth,
            stTime.wDay);
  free(buf);
#else
  char cTime[80];
  timeval curTime;

  char* home = getenv("HOME");
  if (!home) {
    disableLog();
    m_LogType = FILE_LOG;
    return;
  }
  std::string path(home);

  path.append("/.CIEPKI/");

  struct stat st {};

  if (stat(path.c_str(), &st) == -1) {
    mkdir(path.c_str(), 0700);
  }

  gettimeofday(&curTime, nullptr);
  strftime(cTime, sizeof(cTime), "%Y-%m-%d", gmtime(&curTime.tv_sec));

  snprintf(pbLog, sizeof(pbLog), "%s_%s.log", "CIEPKI", cTime);
  path.append(pbLog);

  memcpy(pbLog, path.data(), path.length());
  pbLog[path.length()] = 0;
#endif

  int log_level = getLogConfig();

  if (log_level == LOG_STATUS_DISABLED) {
    disableLog();
  } else {
    m_File.open(pbLog, std::ios::out | std::ios::app);
    m_File
        << '\n'
        << "-----------------------------------------------------------------"
        << '\n'
        << '\n';

#ifdef _WIN32
    char pProcessInfo[MAX_PATH];
    char szModulePath[MAX_PATH];
    size_t l =
        GetModuleFileNameA(nullptr, szModulePath, sizeof(szModulePath) - 1);
    szModulePath[l] = 0;
    sprintf_s(pProcessInfo, sizeof(pProcessInfo), "Process: '%s'",
              szModulePath);
    m_File << pProcessInfo << '\n';
#endif

    m_LogLevel = static_cast<LogLevel>(log_level);
    m_LogStatus = LOG_STATUS_ENABLED;

    m_File.flush();
    m_File.close();
  }

  m_LogType = FILE_LOG;
}

Logger::~Logger() { m_File.close(); }

Logger& Logger::getInstance() noexcept {
  static Logger instance;

#ifndef __ANDROID__
  int log_level = instance.getLogConfig();

  if (log_level == LOG_STATUS_DISABLED) {
    instance.disableLog();
  } else if (log_level >= 0 && log_level < 3) {
    instance.enableFileLogging();
    instance.enableLog();
    instance.updateLogLevel(static_cast<LogLevel>(log_level));
  }
#endif

  return instance;
}

void Logger::writeConfigFile(const std::string& filePath,
                             const std::string& sConfig) noexcept {
  m_ConfigFile.open(filePath, std::ios::out);
  m_ConfigFile << sConfig;
  m_ConfigFile.close();
}

#ifdef _WIN32
static BOOL IsElevated() {
  BOOL fRet = FALSE;
  HANDLE hToken = nullptr;
  if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
    TOKEN_ELEVATION Elevation;
    DWORD cbSize = sizeof(TOKEN_ELEVATION);
    if (GetTokenInformation(hToken, TokenElevation, &Elevation,
                            sizeof(Elevation), &cbSize)) {
      fRet = Elevation.TokenIsElevated;
    }
  }
  if (hToken) {
    CloseHandle(hToken);
  }
  return fRet;
}
#endif

int Logger::getLogConfig() noexcept {
  std::string sConfig;
  int log_level = 0;
  struct stat result;

#ifdef _WIN32
  char* buf = nullptr;
  size_t sz = 0;
  char pbPathConfig[MAX_PATH];

#if defined(_MSC_VER)
  _dupenv_s(&buf, &sz, "PROGRAMDATA");
#else
  if (const char* _pd = getenv("PROGRAMDATA")) {
    sz = strlen(_pd) + 1;
    buf = static_cast<char*>(malloc(sz));
    if (buf) memcpy(buf, _pd, sz);
  }
#endif

  sprintf_s(pbPathConfig, sizeof(pbPathConfig), "%s/CIEPKI",
            buf ? buf : "C:\\ProgramData");
  sprintf_s(pbConfig, sizeof(pbConfig), "%s/config", pbPathConfig);
  free(buf);

  if (IsElevated()) {
    return LOG_STATUS_DISABLED;
  }

  if (!PathFileExists(pbPathConfig)) {
    CreateDirectory(pbPathConfig, nullptr);
  }
#else
  char* home = getenv("HOME");
  if (!home) return LOG_STATUS_DISABLED;
  std::string path(home);

  path.append("/.CIEPKI/");

  // check if folder exist
  struct stat st {};

  if (stat(path.c_str(), &st) == -1) {
    mkdir(path.c_str(), 0700);
  }

  snprintf(pbConfig, sizeof(pbConfig), "%s/config", path.data());
#endif

  if (!config_exists(pbConfig)) {
    sConfig = "LIB_LOG_LEVEL=2";
    std::string stConfig = std::string(pbConfig);
    writeConfigFile(stConfig, sConfig);
    t64configTime = 0;
  }

  volatile int stat_res = stat(pbConfig, &result);

  if (stat_res == 0) {
    if (t64configTime < result.st_mtime) {
      t64configTime = result.st_mtime;

      {
        std::lock_guard<std::mutex> guard(m_Mutex);
        m_ConfigFile.open(pbConfig, std::ios::in);
        m_ConfigFile >> sConfig;
        m_ConfigFile.close();
      }

      sscanf(sConfig.data(), "LIB_LOG_LEVEL=%d", &log_level);

      if (log_level < 0 || log_level > 5) {
        log_level = 0;
        sConfig = "LIB_LOG_LEVEL=2";
        std::string stConfig = std::string(pbConfig);
        writeConfigFile(stConfig, sConfig);
      }

      m_LogLevel = static_cast<LogLevel>(log_level);
    }
  }

  return m_LogLevel;
}

void Logger::logIntoFile(const std::string& data) {
  std::lock_guard<std::mutex> guard(m_Mutex);
  m_File << getCurrentTime() << "  " << data << '\n';
}

void Logger::logOnConsole(const std::string& data) {
  std::cout << getCurrentTime() << "  " << data << '\n';
}

std::string Logger::getCurrentTime() {
#ifdef _WIN32
  char pbtDate[0x1000];
  SYSTEMTIME stTime;
  GetLocalTime(&stTime);

  sprintf_s(pbtDate, sizeof(pbtDate), "%04d-%02d-%02d %02d:%02d:%02d:%03d",
            stTime.wYear, stTime.wMonth, stTime.wDay, stTime.wHour,
            stTime.wMinute, stTime.wSecond, stTime.wMilliseconds);

  return pbtDate;
#else
  // Get the current time as a time_point
  auto now = std::chrono::system_clock::now();

  // Convert to time_t for formatting
  std::time_t now_c = std::chrono::system_clock::to_time_t(now);

  // Convert to local time
  std::tm local_tm = *std::localtime(&now_c);

  // Format the time as a string
  std::ostringstream oss;
  oss << std::put_time(&local_tm, "%Y-%m-%d %H:%M:%S");

  return oss.str();
#endif
}

void Logger::log_log(std::ostream& /*out*/, LogLevel level,
                     const char* text) noexcept {
  if (m_LogStatus == LOG_STATUS_ENABLED) {
    if (level < m_LogLevel) {
      return;
    }

#ifdef __ANDROID__
    android_LogPriority prio;
    switch (level) {
      case LOG_LEVEL_DEBUG:
        prio = ANDROID_LOG_DEBUG;
        break;
      case LOG_LEVEL_INFO:
        prio = ANDROID_LOG_INFO;
        break;
      case LOG_LEVEL_ERROR:
        prio = ANDROID_LOG_ERROR;
        break;
      default:
        prio = ANDROID_LOG_VERBOSE;
        break;
    }
    __android_log_print(prio, CIE_LOG_TAG, "%s", text);
#else
    std::string data;
    data.append(level_strings[level]);
    data.append(" ");
    data.append(text);

    std::lock_guard<std::mutex> guard(m_Mutex);
    m_File.open(pbLog, std::ios::out | std::ios::app);
    m_File << getCurrentTime() << "  " << data << '\n';
    m_File.flush();
    m_File.close();
#endif
  }
}

// Interface for Debug Log
void Logger::debug(const char* fmt, ...) noexcept {
  char logBuffer[8192];
  va_list args;
  va_start(args, fmt);

  vsnprintf(logBuffer, sizeof(logBuffer), fmt, args);
  va_end(args);

  switch (m_LogType) {
    case FILE_LOG:
      log_log(m_File, LOG_LEVEL_DEBUG, logBuffer);
      break;
    case CONSOLE:
      log_log(std::cout, LOG_LEVEL_DEBUG, logBuffer);
    default:
      break;
  }
}

void Logger::debug(const std::string& text) noexcept { debug(text.data()); }

void Logger::debug(const std::ostringstream& stream) noexcept {
  std::string text = stream.str();
  debug(text.data());
}

// Interface for Info Log
void Logger::info(const char* fmt, ...) noexcept {
  char logBuffer[1024];
  va_list args;
  va_start(args, fmt);

  vsnprintf(logBuffer, sizeof(logBuffer), fmt, args);
  va_end(args);

  switch (m_LogType) {
    case FILE_LOG:
      log_log(m_File, LOG_LEVEL_INFO, logBuffer);
      break;
    case CONSOLE:
      log_log(std::cout, LOG_LEVEL_INFO, logBuffer);
    default:
      break;
  }
}

void Logger::info(const std::string& text) noexcept { info(text.data()); }

void Logger::info(const std::ostringstream& stream) noexcept {
  std::string text = stream.str();
  info(text.data());
}

// Interface for Error Log
int Logger::error(const char* fmt, ...) noexcept {
  char logBuffer[1024];
  va_list args;
  va_start(args, fmt);

  vsnprintf(logBuffer, sizeof(logBuffer), fmt, args);
  va_end(args);

  switch (m_LogType) {
    case FILE_LOG:
      log_log(m_File, LOG_LEVEL_ERROR, logBuffer);
      break;
    case CONSOLE:
      log_log(std::cout, LOG_LEVEL_ERROR, logBuffer);
    default:
      break;
  }

  return -1;
}

int Logger::error(const std::string& text) noexcept {
  return error(text.data());
}

int Logger::error(const std::ostringstream& stream) noexcept {
  std::string text = stream.str();
  return error(text.data());
}

// Interface for Buffer Log
void Logger::buffer(const uint8_t* buff, size_t buff_size) noexcept {
  if (m_LogLevel == LOG_LEVEL_DEBUG) {
    switch (m_LogType) {
      case FILE_LOG:
        print_bytes(m_File, buff, buff_size, true);
        break;
      case CONSOLE:
        print_bytes(std::cout, buff, buff_size, true);
      default:
        break;
    }
  }
}

void Logger::print_bytes(std::ostream& /*out*/, const uint8_t* data,
                         size_t dataLen, bool /*format*/) {
  size_t index = 0;

  std::lock_guard<std::mutex> guard(m_Mutex);
  m_File.open(pbLog, std::ios::out | std::ios::app);

  m_File << std::setfill('0');
  m_File << '\n';

  m_File << "0x" << std::hex << std::setw(8) << index << "\t";

  for (size_t idx = 0; idx < dataLen; idx++) {
    if (idx) {
      if ((idx % 16) == 0) {
        m_File << "\n0x" << std::hex << std::setw(8) << idx << "\t";
      } else if ((idx % 8) == 0) {
        m_File << " -  ";
      }
    }

    m_File << std::hex << std::setw(2) << static_cast<int>(data[idx]) << " ";
  }
  m_File << '\n' << '\n';

  m_File.close();
}

void Logger::updateLogLevel(LogLevel logLevel) { m_LogLevel = logLevel; }

void Logger::enableLog() { m_LogStatus = LOG_STATUS_ENABLED; }

void Logger::disableLog() { m_LogStatus = LOG_STATUS_DISABLED; }

void Logger::updateLogType(LogType logType) { m_LogType = logType; }

void Logger::enableConsoleLogging() { m_LogType = CONSOLE; }

void Logger::enableFileLogging() { m_LogType = FILE_LOG; }

}  // namespace CieIDLogger
