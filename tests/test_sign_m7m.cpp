// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

#include <catch2/catch_test_macros.hpp>
#include <string>

#include "m7m_parser.h"

namespace {
int load(const std::string& s) {
  M7MParser p;
  return p.Load(s.data(), static_cast<int>(s.size()));
}
}  // namespace

TEST_CASE("M7MParser parses a well-formed two-part file") {
  const std::string m7m =
      "Content-Type: multipart/mixed; boundary=\"XX\"\r\n\r\n"
      "--XX\r\nContent-Type: application/pkcs7-mime\r\n\r\nP7MDATA\r\n"
      "--XX\r\nContent-Type: application/timestamp-reply\r\n\r\n\x30TSR\r\n"
      "--XX--\r\n";
  M7MParser p;
  REQUIRE(p.Load(m7m.data(), static_cast<int>(m7m.size())) == 0);
  ByteDynArray p7m;
  REQUIRE(p.GetP7M(p7m) == 0);
  CHECK(p7m.size() > 0);
}

TEST_CASE("M7MParser rejects a second part without header separator") {
  // CRLFCRLF only after the closing boundary used to give a negative length.
  const std::string m7m =
      "boundary=\"XX\"\r\n"
      "--XX\r\n\r\n\r\nA\r\n"
      "--XX\r\nno separator here\r\n"
      "--XX--\r\n\r\n\r\n";
  CHECK(load(m7m) == -1);
}

TEST_CASE("M7MParser rejects truncated and empty input") {
  CHECK(load("") == -1);
  CHECK(load("boundary=\"XX") == -1);
  CHECK(load("boundary=\"XX\"\r\n--XX") == -1);
}

TEST_CASE("M7MParser::GetTSR without timestamp part fails cleanly") {
  const std::string m7m =
      "boundary=\"XX\"\r\n"
      "--XX\r\nContent-Type: application/pkcs7-mime\r\n\r\nA\r\n"
      "--XX\r\nContent-Type: application/pkcs7-mime\r\n\r\nB\r\n"
      "--XX--\r\n";
  M7MParser p;
  REQUIRE(p.Load(m7m.data(), static_cast<int>(m7m.size())) == 0);
  ByteDynArray tsr;
  CHECK(p.GetTSR(tsr) != 0);
}
