// SPDX-License-Identifier: LGPL-3.0-or-later
#include <catch2/catch_test_macros.hpp>

#include "crypto/asn_parser.h"
#include "util/array.h"

// ── CASNParser
// ────────────────────────────────────────────────────────────────

TEST_CASE("ASN1 parse simple INTEGER", "[asn1]") {
  // SEQUENCE { INTEGER 0x01 }
  // 30 03 02 01 01
  uint8_t raw[] = {0x30, 0x03, 0x02, 0x01, 0x01};
  ByteDynArray data(ByteArray(raw, sizeof(raw)));

  CASNParser parser;
  parser.Parse(data);

  REQUIRE(parser.tags.size() == 1);
  CHECK(parser.tags[0]->tagInt() == 0x30);  // SEQUENCE
  REQUIRE(parser.tags[0]->tags.size() == 1);
  CHECK(parser.tags[0]->tags[0]->tagInt() == 0x02);  // INTEGER
  CHECK(parser.tags[0]->tags[0]->content[0] == 0x01);
}

TEST_CASE("ASN1 parse OCTET STRING", "[asn1]") {
  // OCTET STRING { 0xDE 0xAD 0xBE 0xEF }
  // 04 04 DE AD BE EF
  uint8_t raw[] = {0x04, 0x04, 0xDE, 0xAD, 0xBE, 0xEF};
  ByteDynArray data(ByteArray(raw, sizeof(raw)));

  CASNParser parser;
  parser.Parse(data);

  REQUIRE(parser.tags.size() == 1);
  CHECK(parser.tags[0]->tagInt() == 0x04);
  REQUIRE(parser.tags[0]->content.size() == 4);
  CHECK(parser.tags[0]->content[0] == 0xDE);
  CHECK(parser.tags[0]->content[3] == 0xEF);
}

TEST_CASE("ASN1 encode round-trip", "[asn1]") {
  uint8_t raw[] = {0x30, 0x03, 0x02, 0x01, 0x42};
  ByteDynArray data(ByteArray(raw, sizeof(raw)));

  CASNParser parser;
  parser.Parse(data);

  ByteDynArray encoded;
  parser.Encode(encoded);

  REQUIRE(encoded.size() == sizeof(raw));
  for (size_t i = 0; i < sizeof(raw); ++i) CHECK(encoded[i] == raw[i]);
}

TEST_CASE("ASN1 CalcLen matches encoded size", "[asn1]") {
  uint8_t raw[] = {0x04, 0x03, 0xAA, 0xBB, 0xCC};
  ByteDynArray data(ByteArray(raw, sizeof(raw)));

  CASNParser parser;
  parser.Parse(data);

  CHECK(parser.CalcLen() == sizeof(raw));
}

TEST_CASE("ASN1 parse multiple top-level tags", "[asn1]") {
  // NULL (05 00) followed by BOOLEAN TRUE (01 01 FF)
  uint8_t raw[] = {0x05, 0x00, 0x01, 0x01, 0xFF};
  ByteDynArray data(ByteArray(raw, sizeof(raw)));

  CASNParser parser;
  parser.Parse(data);

  REQUIRE(parser.tags.size() == 2);
  CHECK(parser.tags[0]->tagInt() == 0x05);
  CHECK(parser.tags[1]->tagInt() == 0x01);
  CHECK(parser.tags[1]->content[0] == 0xFF);
}

TEST_CASE("GetASN1DataLenght short form", "[asn1]") {
  // Tag=0x04, Len=5 (short form): returns total TLV size = 1 (tag) + 1 (len) +
  // 5 (data) = 7
  uint8_t raw[] = {0x04, 0x05};
  ByteArray ba(raw, 2);
  CHECK(GetASN1DataLenght(ba) == 7);
}

TEST_CASE("GetASN1DataLenght long form 1 byte", "[asn1]") {
  // Tag=0x04, Len=0x81 0xC8 (long form, 1 byte: 200): returns total TLV size =
  // 1 + 2 + 200 = 203
  uint8_t raw[] = {0x04, 0x81, 0xC8};
  ByteArray ba(raw, 3);
  CHECK(GetASN1DataLenght(ba) == 203);
}
