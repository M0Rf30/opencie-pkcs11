// SPDX-License-Identifier: LGPL-3.0-or-later
#include <catch2/catch_test_macros.hpp>

#include "util/array.h"
#include "util/util.h"

// ── PutPaddingBT1 / RemovePaddingBT1 ─────────────────────────────────────────

TEST_CASE("PutPaddingBT1 produces correct PKCS#1 type-1 block",
          "[padding][pkcs1]") {
  // 8-byte block, 2-byte data → 00 01 FF FF FF 00 <data>
  ByteDynArray ba(8);
  uint8_t data[] = {0xAA, 0xBB};
  ByteArray bdata(data, 2);
  ba.right(2).copy(bdata);
  PutPaddingBT1(ba, 2);

  CHECK(ba[0] == 0x00);
  CHECK(ba[1] == 0x01);
  // Padding bytes should be 0xFF
  for (size_t i = 2; i < 5; ++i) CHECK(ba[i] == 0xFF);
  CHECK(ba[5] == 0x00);
}

TEST_CASE("RemovePaddingBT1 returns offset past separator",
          "[padding][pkcs1]") {
  // 00 01 FF FF FF 00 AA BB
  uint8_t raw[] = {0x00, 0x01, 0xFF, 0xFF, 0xFF, 0x00, 0xAA, 0xBB};
  ByteArray ba(raw, 8);
  unsigned long offset = RemovePaddingBT1(ba);
  CHECK(offset == 6);  // data starts at index 6
}

TEST_CASE("RemovePaddingBT1 throws on wrong block type", "[padding][pkcs1]") {
  uint8_t raw[] = {0x00, 0x02, 0xFF, 0x00, 0xAA};
  ByteArray ba(raw, 5);
  CHECK_THROWS(RemovePaddingBT1(ba));
}

TEST_CASE("RemovePaddingBT1 throws on non-zero first byte",
          "[padding][pkcs1]") {
  uint8_t raw[] = {0x01, 0x01, 0xFF, 0x00, 0xAA};
  ByteArray ba(raw, 5);
  CHECK_THROWS(RemovePaddingBT1(ba));
}

// ── PutPaddingBT2 / RemovePaddingBT2 ─────────────────────────────────────────

TEST_CASE("PutPaddingBT2 produces correct PKCS#1 type-2 block",
          "[padding][pkcs1]") {
  ByteDynArray ba(10);
  uint8_t data[] = {0x01, 0x02, 0x03};
  ByteArray bdata(data, 3);
  ba.right(3).copy(bdata);
  PutPaddingBT2(ba, 3);

  CHECK(ba[0] == 0x00);
  CHECK(ba[1] == 0x02);
  CHECK(ba[6] == 0x00);  // separator before data
}

TEST_CASE("RemovePaddingBT2 returns offset past separator",
          "[padding][pkcs1]") {
  // 00 02 <random non-zero bytes> 00 <data>
  uint8_t raw[] = {0x00, 0x02, 0x11, 0x22, 0x33, 0x00, 0xAA, 0xBB};
  ByteArray ba(raw, 8);
  unsigned long offset = RemovePaddingBT2(ba);
  CHECK(offset == 6);
}

TEST_CASE("RemovePaddingBT2 throws on wrong block type", "[padding][pkcs1]") {
  uint8_t raw[] = {0x00, 0x01, 0xFF, 0x00, 0xAA};
  ByteArray ba(raw, 5);
  CHECK_THROWS(RemovePaddingBT2(ba));
}

// ── RemoveISOPad
// ──────────────────────────────────────────────────────────────

TEST_CASE("RemoveISOPad returns length before 0x80 marker", "[padding][iso]") {
  // 3 data bytes + 0x80 + 4 zeros = 8 bytes
  uint8_t raw[] = {0xAA, 0xBB, 0xCC, 0x80, 0x00, 0x00, 0x00, 0x00};
  ByteArray ba(raw, 8);
  unsigned long len = RemoveISOPad(ba);
  CHECK(len == 3);
}

TEST_CASE("RemoveISOPad round-trips with ISOPad", "[padding][iso]") {
  uint8_t raw[] = {0x01, 0x02, 0x03, 0x04, 0x05};
  ByteArray ba(raw, 5);
  ByteDynArray padded = ISOPad(ba);

  unsigned long len = RemoveISOPad(padded);
  CHECK(len == 5);
  for (size_t i = 0; i < 5; ++i) CHECK(padded[i] == raw[i]);
}

TEST_CASE("RemoveISOPad throws when no 0x80 marker found", "[padding][iso]") {
  uint8_t raw[] = {0x00, 0x00, 0x00, 0x00};
  ByteArray ba(raw, 4);
  CHECK_THROWS(RemoveISOPad(ba));
}

TEST_CASE("RemoveISOPad throws on non-0x80 non-zero trailing byte",
          "[padding][iso]") {
  uint8_t raw[] = {0xAA, 0xBB, 0x01};  // last non-zero byte is not 0x80
  ByteArray ba(raw, 3);
  CHECK_THROWS(RemoveISOPad(ba));
}

// ── RemoveSha1 / RemoveSha256
// ─────────────────────────────────────────────────

TEST_CASE("RemoveSha1 recognises SHA-1 DigestInfo prefix", "[util][digest]") {
  // SHA-1 DigestInfo OID prefix
  uint8_t prefix[] = {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03,
                      0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
                      // followed by 20 dummy hash bytes
                      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                      0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
                      0x12, 0x13};
  ByteArray ba(prefix, sizeof(prefix));
  unsigned long offset = RemoveSha1(ba);
  CHECK(offset == 15);
}

TEST_CASE("RemoveSha1 throws on wrong prefix", "[util][digest]") {
  uint8_t bad[] = {0x30, 0x31, 0x00};
  ByteArray ba(bad, 3);
  CHECK_THROWS(RemoveSha1(ba));
}

TEST_CASE("RemoveSha256 recognises SHA-256 DigestInfo prefix",
          "[util][digest]") {
  uint8_t prefix[] = {
      0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
      0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
      // 32 dummy hash bytes
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
      0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
  ByteArray ba(prefix, sizeof(prefix));
  unsigned long offset = RemoveSha256(ba);
  CHECK(offset == 19);
}
