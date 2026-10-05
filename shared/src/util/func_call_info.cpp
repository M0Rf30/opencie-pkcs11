// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "util/func_call_info.h"

#include <cstdio>

thread_local size_t tlsCallDepth = 0;
thread_local std::unique_ptr<CFuncCallInfoList> callQueue = nullptr;
extern bool FunctionLog;
extern unsigned int GlobalDepth;
extern bool GlobalParam;
char szEmpty[] = {'\0'};

CFuncCallInfo::CFuncCallInfo(const char *name, CLog &logInfo) : log(logInfo) {
  fName = name;
  if (FunctionLog) {
    if (tlsCallDepth < GlobalDepth) {
      // The '*' width specifier requires an int argument; DWORD is
      // unsigned long on LP64 platforms, a real printf-format mismatch.
      LogNum = logInfo.write("%*sIN -> %s", static_cast<int>(tlsCallDepth),
                             szEmpty, fName);
    }
  }

  tlsCallDepth = tlsCallDepth + 1;
}

CFuncCallInfo::~CFuncCallInfo() {
  tlsCallDepth = tlsCallDepth - 1;
  if (fName)
    log.write("%*sOUT -> %s (%u)", static_cast<int>(tlsCallDepth), szEmpty,
              fName, LogNum - 1);
}

const char *CFuncCallInfo::FunctionName() { return fName; }
