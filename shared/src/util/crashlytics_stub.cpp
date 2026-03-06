// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "definitions.h"
#include "logging_macros.h"

logFunc pfnCrashliticsLog = [](const char* msg) {
  cie_logging::printf_fallback_log(cie_logging::ERROR_LEVEL, "CRASHLYTICS",
                                   "%s", msg ? msg : "null");
};