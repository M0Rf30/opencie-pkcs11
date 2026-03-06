// SPDX-License-Identifier: LGPL-3.0-or-later

#include "util/util_exception.h"

#include "logger/logger.h"
#include "util/util.h"

using namespace CieIDLogger;

logged_error::logged_error(const std::string &message)
    : std::runtime_error(message.c_str()) {
  logged_error(message.c_str());
}

logged_error::logged_error(const char *message) : std::runtime_error(message) {
  LOG_ERROR("%s", message);
}

scard_error::scard_error(StatusWord sw)
    : logged_error(stdPrintf("Errore smart card:%x", sw)) {}

windows_error::windows_error(long ris)
    : logged_error(stdPrintf("Errore windows:(%08x) ", ris)) {}
