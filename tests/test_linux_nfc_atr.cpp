// SPDX-License-Identifier: LGPL-3.0-or-later
#include <catch2/catch_test_macros.hpp>

#include "pcsc/linux_nfc_transport.h"

// ── linuxNfcAtrFromAts ───────────────────────────────────────────────────────
//
// The kernel NFC backend has no ATR to read from the card, so it synthesizes
// one from the ISO 14443-4 ATS. The PKCS#11 slot layer matches CIE chip
// templates on that ATR, so the byte layout matters.

namespace {

uint8_t checksum(const std::vector<uint8_t>& atr) {
  uint8_t tck = 0;
  for (size_t i = 1; i + 1 < atr.size(); ++i) tck ^= atr[i];
  return tck;
}

}  // namespace

TEST_CASE("ATS without interface bytes yields historical bytes verbatim",
          "[linux_nfc][atr]") {
  // TL=05, T0=00 (no TA/TB/TC), historical bytes 80 31 80 66
  const uint8_t ats[] = {0x05, 0x00, 0x80, 0x31, 0x80, 0x66};
  const auto atr = linuxNfcAtrFromAts(ats, sizeof(ats));

  REQUIRE(atr.size() == 9);
  CHECK(atr[0] == 0x3B);
  CHECK(atr[1] == 0x84);  // 0x80 | 4 historical bytes
  CHECK(atr[2] == 0x80);
  CHECK(atr[3] == 0x01);
  CHECK(atr[4] == 0x80);
  CHECK(atr[5] == 0x31);
  CHECK(atr[6] == 0x80);
  CHECK(atr[7] == 0x66);
  CHECK(atr.back() == checksum(atr));
}

TEST_CASE("ATS interface bytes are skipped before historical bytes",
          "[linux_nfc][atr]") {
  // T0=0x70 → TA(1), TB(1) and TC(1) all present, then two historical bytes.
  const uint8_t ats[] = {0x07, 0x70, 0x11, 0x22, 0x33, 0xAA, 0xBB};
  const auto atr = linuxNfcAtrFromAts(ats, sizeof(ats));

  REQUIRE(atr.size() == 7);
  CHECK(atr[1] == 0x82);  // two historical bytes
  CHECK(atr[4] == 0xAA);
  CHECK(atr[5] == 0xBB);
  CHECK(atr.back() == checksum(atr));
}

TEST_CASE("ATS with only interface bytes falls back to the minimal ATR",
          "[linux_nfc][atr]") {
  const uint8_t ats[] = {0x03, 0x10, 0x11};
  const auto atr = linuxNfcAtrFromAts(ats, sizeof(ats));

  CHECK(atr == std::vector<uint8_t> {0x3B, 0x80, 0x80, 0x01, 0x01});
}

TEST_CASE("Absent ATS (type B targets) falls back to the minimal ATR",
          "[linux_nfc][atr]") {
  CHECK(linuxNfcAtrFromAts(nullptr, 0) ==
        std::vector<uint8_t> {0x3B, 0x80, 0x80, 0x01, 0x01});

  const uint8_t truncated[] = {0x01};
  CHECK(linuxNfcAtrFromAts(truncated, sizeof(truncated)) ==
        std::vector<uint8_t> {0x3B, 0x80, 0x80, 0x01, 0x01});
}
