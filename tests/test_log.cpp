// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later
#include <catch2/catch_test_macros.hpp>
#include <ctime>
#include <regex>
#include <string>

#include "util/log.h"

// Regression test for CIE-LOG-001: CLog::init() used to build the log file
// date from raw tm_year (years since 1900, e.g. 126 for 2026) and raw
// tm_mon (0-based), and left the day unpadded, producing file names like
// "CIEPKC11_0126-08-5.log" instead of "CIEPKC11_2026-08-05.log". The date
// is now built once with strftime("%Y-%m-%d", ...) via a small helper.
TEST_CASE(
    "CLog builds a correctly formatted YYYY-MM-DD date in the log "
    "file name",
    "[log]") {
  CLog log;
  REQUIRE_FALSE(log.logPath.empty());

  // The exact layout depends on the process-wide LogMode (LM_Single:
  // "<name>_YYYY-MM-DD.log", LM_Module: "YYYY-MM-DD_<name>.log", ...);
  // LogMode is shared global state that other tests in this binary may
  // have changed, so match the date anywhere rather than anchoring it.
  static const std::regex kDatePattern(R"((\d{4})-(\d{2})-(\d{2}))");
  std::smatch m;
  REQUIRE(std::regex_search(log.logPath, m, kDatePattern));

  int year = std::stoi(m[1].str());
  int month = std::stoi(m[2].str());
  int day = std::stoi(m[3].str());

  // A four-digit calendar year (not tm_year's "years since 1900"), a
  // 1-12 month (not 0-based), and a zero-padded two-digit day.
  time_t now = time(nullptr);
  struct tm tmNow {};
  localtime_r(&now, &tmNow);

  CHECK(year == tmNow.tm_year + 1900);
  CHECK(month == tmNow.tm_mon + 1);
  CHECK(day == tmNow.tm_mday);
  CHECK(m[3].str().size() == 2);
}
