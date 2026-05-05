// SPDX-License-Identifier: LGPL-3.0-or-later
#include <catch2/catch_test_macros.hpp>

#include "util/array.h"
#include "util/util.h"

// ── hex2byte
// ──────────────────────────────────────────────────────────────────

TEST_CASE("hex2byte converts lowercase hex digits", "[util][hex]") {
  CHECK(hex2byte('0') == 0x0);
  CHECK(hex2byte('9') == 0x9);
  CHECK(hex2byte('a') == 0xa);
  CHECK(hex2byte('f') == 0xf);
}

TEST_CASE("hex2byte converts uppercase hex digits", "[util][hex]") {
  CHECK(hex2byte('A') == 0xa);
  CHECK(hex2byte('F') == 0xf);
}

// ── HexByte
// ───────────────────────────────────────────────────────────────────

TEST_CASE("HexByte formats single byte uppercase", "[util][hex]") {
  CHECK(HexByte(0x00) == "00");
  CHECK(HexByte(0xFF) == "FF");
  CHECK(HexByte(0xAB) == "AB");
  CHECK(HexByte(0x0F) == "0F");
}

TEST_CASE("HexByte formats single byte lowercase", "[util][hex]") {
  CHECK(HexByte(0xAB, false) == "ab");
  CHECK(HexByte(0xFF, false) == "ff");
}

// ── dumpHexData
// ───────────────────────────────────────────────────────────────

TEST_CASE("dumpHexData produces uppercase hex string", "[util][hex]") {
  uint8_t raw[] = {0xDE, 0xAD, 0xBE, 0xEF};
  ByteArray ba(raw, 4);
  std::string dump;
  dumpHexData(ba, dump);
  // Default: uppercase with spaces
  CHECK(dump.find("DE") != std::string::npos);
  CHECK(dump.find("AD") != std::string::npos);
}

TEST_CASE("dumpHexData standalone overload returns string", "[util][hex]") {
  uint8_t raw[] = {0x01, 0x02, 0x03};
  ByteArray ba(raw, 3);
  std::string result = dumpHexData(ba);
  CHECK(!result.empty());
  CHECK(result.find("01") != std::string::npos);
}

TEST_CASE("dumpHexDataLowerCase produces lowercase hex", "[util][hex]") {
  uint8_t raw[] = {0xAB, 0xCD};
  ByteArray ba(raw, 2);
  std::string dump;
  dumpHexDataLowerCase(ba, dump);
  CHECK(dump.find("ab") != std::string::npos);
  CHECK(dump.find("cd") != std::string::npos);
}

// ── readHexData
// ───────────────────────────────────────────────────────────────

TEST_CASE("readHexData parses hex string into ByteDynArray", "[util][hex]") {
  ByteDynArray ba;
  readHexData("DEADBEEF", ba);
  REQUIRE(ba.size() == 4);
  CHECK(ba[0] == 0xDE);
  CHECK(ba[1] == 0xAD);
  CHECK(ba[2] == 0xBE);
  CHECK(ba[3] == 0xEF);
}

TEST_CASE("readHexData handles lowercase hex", "[util][hex]") {
  ByteDynArray ba;
  readHexData("deadbeef", ba);
  REQUIRE(ba.size() == 4);
  CHECK(ba[0] == 0xDE);
  CHECK(ba[3] == 0xEF);
}

TEST_CASE("readHexData round-trips with dumpHexData", "[util][hex]") {
  uint8_t raw[] = {0x12, 0x34, 0x56, 0x78};
  ByteArray ba(raw, 4);
  std::string dump;
  dumpHexData(ba, dump, false, true);  // no spaces, uppercase

  ByteDynArray result;
  readHexData(dump, result);
  REQUIRE(result.size() == 4);
  for (size_t i = 0; i < 4; ++i) CHECK(result[i] == raw[i]);
}

// ── ByteArrayToInt
// ────────────────────────────────────────────────────────────

TEST_CASE("ByteArrayToInt converts big-endian bytes to int", "[util]") {
  uint8_t raw[] = {0x00, 0x01};
  ByteArray ba(raw, 2);
  CHECK(ByteArrayToInt(ba) == 1);
}

TEST_CASE("ByteArrayToInt converts multi-byte value", "[util]") {
  uint8_t raw[] = {0x01, 0x00};
  ByteArray ba(raw, 2);
  CHECK(ByteArrayToInt(ba) == 256);
}

TEST_CASE("ByteArrayToInt single byte", "[util]") {
  uint8_t raw[] = {0x42};
  ByteArray ba(raw, 1);
  CHECK(ByteArrayToInt(ba) == 0x42);
}

// ── ISOPad / ISOPad16
// ─────────────────────────────────────────────────────────

TEST_CASE("ISOPad pads data to 8-byte boundary", "[util][padding]") {
  uint8_t raw[] = {0x01, 0x02, 0x03};
  ByteArray ba(raw, 3);
  ByteDynArray padded = ISOPad(ba);
  // 3 bytes + 0x80 + 4 zeros = 8 bytes
  REQUIRE(padded.size() == 8);
  CHECK(padded[3] == 0x80);
  CHECK(padded[4] == 0x00);
  CHECK(padded[7] == 0x00);
}

TEST_CASE("ISOPad on already-aligned data adds full padding block",
          "[util][padding]") {
  uint8_t raw[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
  ByteArray ba(raw, 8);
  ByteDynArray padded = ISOPad(ba);
  // 8 bytes already aligned → adds 8-byte padding block
  REQUIRE(padded.size() == 16);
  CHECK(padded[8] == 0x80);
}

TEST_CASE("ISOPad16 pads data to 16-byte boundary", "[util][padding]") {
  uint8_t raw[] = {0xAA, 0xBB};
  ByteArray ba(raw, 2);
  ByteDynArray padded = ISOPad16(ba);
  REQUIRE(padded.size() == 16);
  CHECK(padded[0] == 0xAA);
  CHECK(padded[1] == 0xBB);
  CHECK(padded[2] == 0x80);
  CHECK(padded[15] == 0x00);
}

// ── ASN1Tag
// ───────────────────────────────────────────────────────────────────

TEST_CASE("ASN1Tag wraps content with tag and length", "[util][asn1]") {
  uint8_t raw[] = {0x01, 0x02, 0x03};
  ByteArray content(raw, 3);
  ByteDynArray tagged = ASN1Tag(0x04, content);
  // Should be: 04 03 01 02 03
  REQUIRE(tagged.size() == 5);
  CHECK(tagged[0] == 0x04);
  CHECK(tagged[1] == 0x03);
  CHECK(tagged[2] == 0x01);
  CHECK(tagged[3] == 0x02);
  CHECK(tagged[4] == 0x03);
}

TEST_CASE("ASN1Tag with empty content produces minimal TLV", "[util][asn1]") {
  uint8_t raw[] = {};
  ByteArray content(raw, 0);
  ByteDynArray tagged = ASN1Tag(0x05, content);
  // Should be: 05 00
  REQUIRE(tagged.size() == 2);
  CHECK(tagged[0] == 0x05);
  CHECK(tagged[1] == 0x00);
}
