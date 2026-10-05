// SPDX-FileCopyrightText: 2026 Gianluca Boiano
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

TEST_CASE("Actalis B946 applet ATR is recognized", "[atr]") {
  // Full PC/SC ATR reported by an Alcor AK9567 contactless slot
  // (opencie issue #34).
  const std::vector<uint8_t> atr = {0x3B, 0x8F, 0x80, 0x01, 0x80, 0x31, 0x80,
                                    0x65, 0x49, 0x54, 0x4A, 0x34, 0x4C, 0x12,
                                    0x0F, 0xFF, 0x82, 0x90, 0x00, 0x85};
  CHECK(get_type(atr) == CIE_Type::CIE_ACTALIS3);
  CHECK(get_manufacturer(atr) == "Actalis_B946");
}

// ── cie_family / get_family_type ────────────────────────────────────────────

TEST_CASE("cie_family collapses revision variants onto their family",
          "[atr][family]") {
  CHECK(cie_family(CIE_Gemalto2) == CIE_Gemalto);
  CHECK(cie_family(CIE_ACTALIS2) == CIE_ACTALIS);
  CHECK(cie_family(CIE_ACTALIS3) == CIE_ACTALIS);
  CHECK(cie_family(CIE_BIT4ID2) == CIE_BIT4ID);
  CHECK(cie_family(CIE_BIT4ID3) == CIE_BIT4ID);

  for (CIE_Type t : {CIE_Unknown, CIE_Gemalto, CIE_STM, CIE_STM2, CIE_STM3,
                     CIE_NXP, CIE_ACTALIS, CIE_BIT4ID})
    CHECK(cie_family(t) == t);
}

TEST_CASE("Every known ATR resolves to the family the protocol layer expects",
          "[atr][family]") {
  const std::vector<uint8_t> itj4Prefix = {0x3B, 0x8F, 0x80, 0x01, 0x80, 0x31,
                                           0x80, 0x65, 0x49, 0x54, 0x4A, 0x34};
  auto itj4 = [&](uint8_t variant, uint8_t tck) {
    std::vector<uint8_t> a = itj4Prefix;
    for (uint8_t b : {variant, uint8_t {0x12}, uint8_t {0x0F}, uint8_t {0xFF},
                      uint8_t {0x82}, uint8_t {0x90}, uint8_t {0x00}, tck})
      a.push_back(b);
    return a;
  };

  CHECK(get_family_type({0x3B, 0x8F, 0x80, 0x01, 0x80, 0x31, 0x80, 0x65, 0x49,
                         0x54, 0x4E, 0x58, 0x50}) == CIE_NXP);
  CHECK(get_family_type({0x3B, 0x8F, 0x80, 0x01, 0x80, 0x31, 0x80, 0x65, 0xB0,
                         0x85, 0x04, 0x00, 0x11}) == CIE_Gemalto);
  CHECK(get_family_type({0x3B, 0x8F, 0x80, 0x01, 0x80, 0x31, 0x80, 0x65, 0xB0,
                         0x85, 0x03, 0x00, 0xEF}) == CIE_Gemalto);
  CHECK(get_family_type(
            {0x3B, 0x80, 0x66, 0x47, 0x50, 0x00, 0xB8, 0x00, 0x7F}) == CIE_STM);
  CHECK(get_family_type({0x3B, 0x80, 0x80, 0x01, 0x01}) == CIE_STM2);
  CHECK(get_family_type({0x3B, 0x8F, 0x80, 0x01, 0x80, 0x66, 0x47, 0x50, 0x00,
                         0xB8, 0x00, 0x94, 0x82, 0x90, 0x00, 0xC5}) ==
        CIE_STM3);
  CHECK(get_family_type(itj4(0x41, 0x88)) == CIE_ACTALIS);
  CHECK(get_family_type(itj4(0x43, 0x8A)) == CIE_ACTALIS);
  CHECK(get_family_type(itj4(0x4C, 0x85)) == CIE_ACTALIS);
  CHECK(get_family_type(itj4(0x42, 0x8B)) == CIE_BIT4ID);
  CHECK(get_family_type(itj4(0x44, 0x8D)) == CIE_BIT4ID);
  CHECK(get_family_type(itj4(0x49, 0x80)) == CIE_BIT4ID);
}

TEST_CASE("Listed ATRs use the exact table, not the fallback",
          "[atr][family]") {
  const std::vector<uint8_t> atr = {0x3B, 0x8F, 0x80, 0x01, 0x80, 0x31, 0x80,
                                    0x65, 0x49, 0x54, 0x4A, 0x34, 0x42, 0x12,
                                    0x0F, 0xFF, 0x82, 0x90, 0x00, 0x8B};
  bool fallback = true;
  CHECK(get_family_type(atr, &fallback) == CIE_BIT4ID);
  CHECK_FALSE(fallback);
}

TEST_CASE("Unlisted ITJ4 variant falls back to the Actalis family",
          "[atr][family]") {
  // Same shape as the listed Actalis/Bit4id ATRs, invented variant byte 0x4F.
  const std::vector<uint8_t> atr = {0x3B, 0x8F, 0x80, 0x01, 0x80, 0x31, 0x80,
                                    0x65, 0x49, 0x54, 0x4A, 0x34, 0x4F, 0x12,
                                    0x0F, 0xFF, 0x82, 0x90, 0x00, 0x82};
  CHECK(get_type(atr) == CIE_Unknown);  // get_type() stays exact
  bool fallback = false;
  CHECK(get_family_type(atr, &fallback) == CIE_ACTALIS);
  CHECK(fallback);
  CHECK(get_manufacturer(atr) == "Actalis");
}

TEST_CASE("ATR with all-zero historical bytes is unsupported",
          "[atr][family]") {
  const std::vector<uint8_t> atr = {0x3B, 0x8F, 0x80, 0x01, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0xFF, 0x82, 0x90, 0x00, 0xE3};
  bool fallback = true;
  CHECK(get_type(atr) == CIE_Unknown);
  CHECK(get_family_type(atr, &fallback) == CIE_Unknown);
  CHECK_FALSE(fallback);
  CHECK(get_manufacturer(atr).empty());
}

TEST_CASE("atr_to_hex formats upper-case space-separated bytes",
          "[atr][family]") {
  CHECK(atr_to_hex({0x3B, 0x0A, 0xFF}) == "3B 0A FF");
  CHECK(atr_to_hex({}).empty());
}
