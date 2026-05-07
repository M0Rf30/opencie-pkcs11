// SPDX-License-Identifier: LGPL-3.0-or-later
#define __STDC_WANT_LIB_EXT1__ 1

#include "util/log.h"

#ifdef _WIN32
// clang-format off
#include <winsock2.h>
#include <direct.h>
#include <io.h>
#include <windows.h>
// clang-format on
#else
#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include <cstdio>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <thread>

#include "module_info.h"
#include "properties.h"

std::string globalLogDir;
std::string globalLogName;
bool FunctionLog = false;
bool globalLogParam = false;
bool firstGlobal = false;
const char *logGlobalVersion;
unsigned int GlobalDepth = 0;
bool mainInit = false;
bool mainEnable = false;
unsigned int GlobalCount;

enum logMode {
  LM_Single,
  LM_Module,
  LM_Thread,
  LM_Module_Thread
} LogMode = LM_Module;

void initLog(const char *moduleName, const char * /*iniFile*/,
             const char *version) {
  if (mainInit) return;

  mainInit = true;

  logGlobalVersion = version;

  Properties settings;

  LogMode = static_cast<logMode>(
      settings.getIntProperty("LogMode", static_cast<int>(LM_Single)));

  if (LogMode != LM_Single && LogMode != LM_Module && LogMode != LM_Thread &&
      LogMode != LM_Module_Thread) {
    LogMode = LM_Single;
  }

  mainEnable = settings.getIntProperty("LogEnable", 1);

  FunctionLog = settings.getIntProperty("FunctionLog", 1);

  GlobalDepth = settings.getIntProperty("FunctionDepth", 10);

  globalLogParam = settings.getIntProperty("ParamLog", 1);

  globalLogName = moduleName;

#ifdef _WIN32
  char szLogDir[MAX_PATH];
  char *buf = nullptr;
  size_t sz = 0;
#if defined(_MSC_VER)
  _dupenv_s(&buf, &sz, "PROGRAMDATA");
#else
  if (const char *_pd = getenv("PROGRAMDATA")) {
    sz = strlen(_pd) + 1;
    buf = static_cast<char *>(malloc(sz));
    if (buf) memcpy(buf, _pd, sz);
  }
#endif
  if (buf) {
    sprintf_s(szLogDir, sizeof(szLogDir), "%s\\CIEPKI\\", buf);
    free(buf);
  } else {
    strcpy_s(szLogDir, sizeof(szLogDir), "C:\\ProgramData\\CIEPKI\\");
  }

  if (GetFileAttributesA(szLogDir) == INVALID_FILE_ATTRIBUTES) {
    CreateDirectoryA(szLogDir, nullptr);
  }

  std::string path(szLogDir);
#else
  char *home = getenv("HOME");
  if (home == nullptr) {
    const struct passwd *pw = getpwuid(getuid());

    home = pw->pw_dir;
    printf("home: %s", home);
  }

  std::string path(home);

  path.append("/.CIEPKI/");

  struct stat st {};

  if (stat(path.c_str(), &st) == -1) {
    mkdir(path.c_str(), 0700);
  }
#endif

  globalLogDir = settings.getProperty("LogDir", path.c_str());
}

CLog::CLog() : FunctionLog(false), ModuleNum(0), _stack_logged(false) {
  init();
}

CLog::~CLog() {
  Enabled = false;
  FirstLog = false;
}

void CLog::init() {
  Enabled = mainEnable;
  LogParam = globalLogParam;
  LogCount = 0;
  logName = globalLogName;
  logFileName = globalLogName;

  std::stringstream th;
  th << std::setw(8) << std::setfill('0');

#ifdef _WIN32
  SYSTEMTIME stTime;
  GetLocalTime(&stTime);
  int year = stTime.wYear;
  int mon = stTime.wMonth;
  int mday = stTime.wDay;
#else
  time_t T = time(nullptr);
  struct tm t;
  struct tm tm = *localtime_r(&T, &t);
  int year = tm.tm_year;
  int mon = tm.tm_mon;
  int mday = tm.tm_mday;
#endif

  switch (LogMode) {
    case (LM_Single): {
      th << logFileName << "_" << std::setw(4) << year << "-" << std::setw(2)
         << mon << "-" << mday << ".log";
      break;
    }
    case (LM_Module): {
      th << std::setw(4) << year << "-" << std::setw(2) << mon << "-" << mday
         << "_" << logFileName << ".log";
      break;
    }
    case (LM_Thread): {
      th << std::setw(4) << year << "-" << std::setw(2) << mon << "-" << mday
         << "_00000000.log";
      break;
    }
    case (LM_Module_Thread): {
      th << std::setw(4) << year << "-" << std::setw(2) << mon << "-" << mday
         << "_" << logFileName << "_00000000.log";
      break;
    }
  }

  logPath = th.str();

  if ((LogMode == LM_Module || LogMode == LM_Module_Thread) &&
      logDir.length() != 0) {
    std::string path = logPath;
    logPath = logDir.append(path);
  } else if (!globalLogDir.empty()) {
    std::string path = logPath;
    logPath = globalLogDir.append(path);
  }
  threadPos = logPath.begin() + logPath.length() - 12;
  Initialized = true;

  if (LogMode != LM_Module && LogMode != LM_Module_Thread && Enabled)
    writePure("Module %02i: %s", ModuleNum, logName.c_str());
}

DWORD CLog::write(const char *format, ...) {
  va_list params;
  va_start(params, format);
  char pbtDate[20] = {0};
  const unsigned int *Num = nullptr;

  if (Enabled && Initialized && mainEnable) {
    if (!firstGlobal && LogMode == LM_Single) {
      firstGlobal = true;
    }
    if (!FirstLog && (LogMode == LM_Module || LogMode == LM_Module_Thread)) {
      FirstLog = true;
    }

    switch (LogMode) {
      case (LM_Module):
        Num = &LogCount;
        break;
      case (LM_Module_Thread):
      case (LM_Thread):
        break;
      case (LM_Single):
        Num = &GlobalCount;
        break;
    }

#ifdef _WIN32
    SYSTEMTIME stTime;
    GetLocalTime(&stTime);
    snprintf(pbtDate, 20, "%05u:[%02d:%02d:%02d]", *Num, stTime.wHour,
             stTime.wMinute, stTime.wSecond);
#else
    time_t T = time(nullptr);
    struct tm t;
    struct tm tm = *localtime_r(&T, &t);
    snprintf(pbtDate, 20, "%05u:[%02d:%02d:0%02d]", *Num, tm.tm_hour, tm.tm_min,
             tm.tm_sec);
#endif

    std::hash<std::thread::id> hasher;
    auto dwThreadID = hasher(std::this_thread::get_id());
    if (LogMode == LM_Thread || LogMode == LM_Module_Thread) {
      std::stringstream th;
      th << std::setiosflags(std::ios::hex | std::ios::uppercase);
      th << std::setw(8);
      th << dwThreadID << ".log";

      logPath.replace(threadPos, threadPos + 14, th.str());
    }
    FILE *lf = nullptr;

#ifdef _WIN32
    fopen_s(&lf, logPath.c_str(), "a+t");
#else
    lf = fopen(logPath.c_str(), "a+t");
#endif
    if (lf) {
#ifndef _WIN32
      struct stat lstat_buf;
      struct stat fstat_buf;

      int r = lstat(logPath.c_str(), &lstat_buf);

      if (r == -1) {
        fclose(lf);
        va_end(params);
        return ERROR_FILE_NOT_FOUND;
      }

      if (S_ISLNK(lstat_buf.st_mode)) {
        fclose(lf);
        va_end(params);
        return static_cast<long>(ERROR_FILE_NOT_FOUND);
      }

      r = stat(logPath.c_str(), &fstat_buf);
      if (r == -1) {
        fclose(lf);
        va_end(params);
        return static_cast<long>(ERROR_FILE_NOT_FOUND);
      }

      if (lstat_buf.st_dev != fstat_buf.st_dev ||
          lstat_buf.st_ino != fstat_buf.st_ino ||
          (S_IFMT & lstat_buf.st_mode) != (S_IFMT & fstat_buf.st_mode)) {
        fclose(lf);
        va_end(params);
        return static_cast<long>(ERROR_FILE_NOT_FOUND);
      }
#endif

      switch (LogMode) {
        case (LM_Single):
#ifdef _WIN32
          fprintf(lf, "%s|%04lu|%04lx|%02u|", pbtDate,
                  (unsigned long)GetCurrentProcessId(),
                  (unsigned long)dwThreadID, ModuleNum);
#else
          fprintf(lf, "%s|%04d|%04lx|%02u|", pbtDate, getpid(), dwThreadID,
                  ModuleNum);
#endif
          break;
        case (LM_Module):
#ifdef _WIN32
          fprintf(lf, "%s|%04lu|%04lx|", pbtDate,
                  (unsigned long)GetCurrentProcessId(),
                  (unsigned long)dwThreadID);
#else
          fprintf(lf, "%s|%04d|%04lx|", pbtDate, getpid(), dwThreadID);
#endif
          break;
        case (LM_Thread):
#ifdef _WIN32
          fprintf(lf, "%s|%04lu|%02u|", pbtDate,
                  (unsigned long)GetCurrentProcessId(), ModuleNum);
#else
          fprintf(lf, "%s|%04d|%02u|", pbtDate, getpid(), ModuleNum);
#endif
          break;
        case (LM_Module_Thread):
          fprintf(lf, "%s|", pbtDate);
          break;
      }
      vfprintf(lf, format, params);
      fprintf(lf, "\n");
      fclose(lf);
    }
  }

#ifdef _DEBUG
  puts(pbtDate);
#endif
  va_end(params);
  if (Num != nullptr) {
    switch (LogMode) {
      case (LM_Module):
        LogCount++;
        break;
      case (LM_Module_Thread):
      case (LM_Thread):
        break;
      case (LM_Single):
        GlobalCount++;
        break;
    }
    return (*Num);
  }
  return 0;
}

void CLog::writePure(const char *format, ...) {
  va_list params;
  va_start(params, format);
  if (Enabled && Initialized && mainEnable) {
    if (!firstGlobal && LogMode == LM_Single) {
      firstGlobal = true;
    }
    if (!FirstLog && (LogMode == LM_Module || LogMode == LM_Module_Thread)) {
      FirstLog = true;
    }

    std::hash<std::thread::id> hasher;
    auto dwThreadID = hasher(std::this_thread::get_id());
    if (LogMode == LM_Thread || LogMode == LM_Module_Thread) {
      std::stringstream th;
      th << std::setiosflags(std::ios::hex | std::ios::uppercase);
      th << std::setw(8);
      th << dwThreadID << ".log";

      logPath.replace(threadPos, threadPos + 14, th.str());
    }
#ifdef _WIN32
    FILE *lf = nullptr;
    fopen_s(&lf, logPath.c_str(), "a+t");
    if (lf) {
      vfprintf(lf, format, params);
      fprintf(lf, "\n");
      fclose(lf);
    }
#endif
  }

  va_end(params);
}

void CLog::writeBinData(BYTE *data, size_t datalen) {
  if (!Enabled || !Initialized || !mainEnable) return;
  if (!firstGlobal && LogMode == LM_Single) {
    firstGlobal = true;
  }
  if (!FirstLog && (LogMode == LM_Module || LogMode == LM_Module_Thread)) {
    FirstLog = true;
  }

  std::hash<std::thread::id> hasher;
  auto dwThreadID = hasher(std::this_thread::get_id());
  if (LogMode == LM_Thread || LogMode == LM_Module_Thread) {
    std::stringstream th;
    th << std::setiosflags(std::ios::hex | std::ios::uppercase);
    th << std::setw(8);
    th << dwThreadID << ".log";

    logPath.replace(threadPos, threadPos + 14, th.str());
  }

  FILE *lf = nullptr;
#ifdef _WIN32
  fopen_s(&lf, logPath.c_str(), "a+t");
#else
  lf = fopen(logPath.c_str(), "a+t");
#endif
  if (lf) {
#ifndef _WIN32
    struct stat lstat_buf;
    struct stat fstat_buf;

    int r = lstat(logPath.c_str(), &lstat_buf);

    if (r == -1) {
      fclose(lf);
      return;
    }

    if (S_ISLNK(lstat_buf.st_mode)) {
      fclose(lf);
      return;
    }

    r = stat(logPath.c_str(), &fstat_buf);
    if (r == -1) {
      fclose(lf);
      return;
    }

    if (lstat_buf.st_dev != fstat_buf.st_dev ||
        lstat_buf.st_ino != fstat_buf.st_ino ||
        (S_IFMT & lstat_buf.st_mode) != (S_IFMT & fstat_buf.st_mode)) {
      fclose(lf);
      return;
    }
#endif

    if (datalen > 100) datalen = 100;
    for (size_t i = 0; i < datalen; i++) fprintf(lf, "%02x ", data[i]);
    fprintf(lf, "\n");
    fclose(lf);
  }
}
