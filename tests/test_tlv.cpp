// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later
#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <cstring>

#include "util/array.h"
#include "util/tlv.h"

// ── CTLV (parser) ────────────────────────────────────────────────────────────

TEST_CASE("CTLV parses single short TLV", "[tlv]") {
  // Tag=0x01, Len=0x03, Value={0xAA,0xBB,0xCC}
  uint8_t raw[] = {0x01, 0x03, 0xAA, 0xBB, 0xCC};
  ByteDynArray data(ByteArray(raw, sizeof(raw)));
  CTLV tlv(data);

  ByteArray *tag = tlv.getTAG(0x01);
  REQUIRE(tag != nullptr);

  ByteArray val = tlv.getValue(0x01);
  REQUIRE(val.size() == 3);
  CHECK(val[0] == 0xAA);
  CHECK(val[1] == 0xBB);
  CHECK(val[2] == 0xCC);
}

TEST_CASE("CTLV parses multiple TLV entries", "[tlv]") {
  // Tag=0x01 Len=2 Val={0x11,0x22}  Tag=0x02 Len=1 Val={0x33}
  uint8_t raw[] = {0x01, 0x02, 0x11, 0x22, 0x02, 0x01, 0x33};
  ByteDynArray data(ByteArray(raw, sizeof(raw)));
  CTLV tlv(data);

  ByteArray v1 = tlv.getValue(0x01);
  REQUIRE(v1.size() == 2);
  CHECK(v1[0] == 0x11);
  CHECK(v1[1] == 0x22);

  ByteArray v2 = tlv.getValue(0x02);
  REQUIRE(v2.size() == 1);
  CHECK(v2[0] == 0x33);
}

TEST_CASE("CTLV returns nullptr for missing tag", "[tlv]") {
  uint8_t raw[] = {0x01, 0x01, 0xFF};
  ByteDynArray data(ByteArray(raw, sizeof(raw)));
  CTLV tlv(data);
  CHECK(tlv.getTAG(0x99) == nullptr);
}

TEST_CASE("CTLV getValue returns empty for missing tag", "[tlv]") {
  uint8_t raw[] = {0x01, 0x01, 0xFF};
  ByteDynArray data(ByteArray(raw, sizeof(raw)));
  CTLV tlv(data);
  ByteArray val = tlv.getValue(0x42);
  CHECK(val.isEmpty());
}

TEST_CASE("CTLV throws on truncated short-form value", "[tlv]") {
  // Len says 5 bytes but only 2 follow — must throw, not silently truncate.
  uint8_t raw[] = {0x01, 0x05, 0xAA, 0xBB};
  ByteDynArray data(ByteArray(raw, sizeof(raw)));
  CHECK_THROWS_AS(CTLV {data}, logged_error);
}

TEST_CASE("CTLV throws on truncated TLV header (single trailing byte)",
          "[tlv]") {
  uint8_t raw[] = {0x01};
  ByteDynArray data(ByteArray(raw, sizeof(raw)));
  CHECK_THROWS_AS(CTLV {data}, logged_error);
}

TEST_CASE("CTLV throws on truncated long-form length header", "[tlv]") {
  // Tag=0x01, len byte 0xFF (long form) but fewer than 4 length octets
  // follow.
  uint8_t raw[] = {0x01, 0xFF, 0x00, 0x00};
  ByteDynArray data(ByteArray(raw, sizeof(raw)));
  CHECK_THROWS_AS(CTLV {data}, logged_error);
}

TEST_CASE("CTLV round-trips a long-form (>=255 byte) value", "[tlv]") {
  const uint32_t contentLen = 300;
  ByteDynArray data(2 + sizeof(uint32_t) + contentLen);
  data[0] = 0x07;
  data[1] = 0xFF;
  uint32_t len = contentLen;
  std::memcpy(data.data() + 2, &len, sizeof(len));
  for (uint32_t i = 0; i < contentLen; i++)
    data[2 + sizeof(uint32_t) + i] = static_cast<uint8_t>(i & 0xFF);

  CTLV tlv(data);
  ByteArray val = tlv.getValue(0x07);
  REQUIRE(val.size() == contentLen);
  CHECK(val[0] == 0x00);
  CHECK(val[299] == static_cast<uint8_t>(299 & 0xFF));
}

// ── CTLVCreate (builder)
// ──────────────────────────────────────────────────────

TEST_CASE("CTLVCreate round-trip: build then parse", "[tlv]") {
  CTLVCreate builder;

  uint8_t v1[] = {0xDE, 0xAD};
  ByteArray ba1(v1, 2);
  builder.setValue(0x10, ba1);

  uint8_t v2[] = {0xBE, 0xEF, 0x00};
  ByteArray ba2(v2, 3);
  builder.setValue(0x20, ba2);

  ByteDynArray buf = builder.getBuffer();

  // Re-parse
  CTLV tlv(buf);

  ByteArray r1 = tlv.getValue(0x10);
  REQUIRE(r1.size() == 2);
  CHECK(r1[0] == 0xDE);
  CHECK(r1[1] == 0xAD);

  ByteArray r2 = tlv.getValue(0x20);
  REQUIRE(r2.size() == 3);
  CHECK(r2[0] == 0xBE);
  CHECK(r2[1] == 0xEF);
}

TEST_CASE("CTLVCreate addValue returns writable buffer", "[tlv]") {
  CTLVCreate builder;
  ByteDynArray *buf = builder.addValue(0x05);
  REQUIRE(buf != nullptr);
  buf->push(0x42);

  ByteDynArray out = builder.getBuffer();
  CTLV tlv(out);
  ByteArray val = tlv.getValue(0x05);
  REQUIRE(val.size() == 1);
  CHECK(val[0] == 0x42);
}

TEST_CASE("CTLVCreate getValue returns nullptr for missing tag", "[tlv]") {
  CTLVCreate builder;
  CHECK(builder.getValue(0xFF) == nullptr);
}

TEST_CASE("CTLVCreate getBuffer is empty when no entries", "[tlv]") {
  CTLVCreate builder;
  ByteDynArray buf = builder.getBuffer();
  CHECK(buf.isEmpty());
}
