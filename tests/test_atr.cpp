// SPDX-License-Identifier: LGPL-3.0-or-later
#include <catch2/catch_test_macros.hpp>

#include "csp/atr.h"

// ── get_manufacturer / get_type ─────────────────────────────────────────────
//
// Matching must require the known signature bytes to appear contiguously and
// in order within the card's ATR, mirroring IAS::ReadCIEType's use of
// ByteArray::indexOf. A weaker order-independent multiset match would accept
// ATRs whose bytes are merely a permutation/superset of a known signature.

TEST_CASE("Known STM2 signature is recognized when present contiguously",
          "[atr]") {
  const std::vector<uint8_t> atr = {0x3B, 0x80, 0x80, 0x01, 0x01};
  CHECK(get_type(atr) == CIE_Type::CIE_STM2);
  CHECK(get_manufacturer(atr) == "STM2");
}

TEST_CASE("Unknown ATR is not recognized", "[atr]") {
  const std::vector<uint8_t> atr = {0x00, 0x11, 0x22, 0x33};
  CHECK(get_type(atr) == CIE_Type::CIE_Unknown);
  CHECK(get_manufacturer(atr).empty());
}

TEST_CASE("Same bytes out of order must NOT match (rejects multiset inclusion)",
          "[atr]") {
  // STM2 signature is {0x80, 0x80, 0x01, 0x01}. A card returning the same
  // multiset of bytes but scattered/reordered must not be misidentified.
  const std::vector<uint8_t> scrambled = {0x01, 0x80, 0x01, 0x80};
  CHECK(get_type(scrambled) == CIE_Type::CIE_Unknown);
  CHECK(get_manufacturer(scrambled).empty());
}

TEST_CASE("Signature bytes scattered across a longer ATR must NOT match",
          "[atr]") {
  // Contains every byte of the STM2 signature {0x80, 0x80, 0x01, 0x01} as a
  // multiset, but not contiguously/in-order.
  const std::vector<uint8_t> scattered = {0x80, 0xFF, 0x80, 0xFF,
                                          0x01, 0xFF, 0x01};
  CHECK(get_type(scattered) == CIE_Type::CIE_Unknown);
}

TEST_CASE("Signature embedded contiguously inside a longer ATR still matches",
          "[atr]") {
  const std::vector<uint8_t> atr = {0x3B, 0x84, 0x80, 0x80, 0x01, 0x01, 0x00};
  CHECK(get_type(atr) == CIE_Type::CIE_STM2);
}
