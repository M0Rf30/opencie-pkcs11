// SPDX-License-Identifier: LGPL-3.0-or-later
#include <catch2/catch_test_macros.hpp>

#include "crypto/asn_parser.h"
#include "util/array.h"

// ── CASNTag: tagInt
// ───────────────────────────────────────────────────────────

TEST_CASE("CASNTag tagInt returns correct value after parse", "[asn1][tag]") {
  uint8_t raw[] = {0x02, 0x01, 0x07};  // INTEGER 7
  ByteDynArray data(ByteArray(raw, sizeof(raw)));
  CASNParser parser;
  parser.Parse(data);
  REQUIRE(parser.tags.size() == 1);
  CHECK(parser.tags[0]->tagInt() == 0x02);
}

// ── CASNTag: EncodeLen
// ────────────────────────────────────────────────────────

TEST_CASE("CASNTag EncodeLen matches raw input size", "[asn1][tag]") {
  // OCTET STRING { 0xAA 0xBB 0xCC } → 04 03 AA BB CC = 5 bytes
  uint8_t raw[] = {0x04, 0x03, 0xAA, 0xBB, 0xCC};
  ByteDynArray data(ByteArray(raw, sizeof(raw)));
  CASNParser parser;
  parser.Parse(data);
  REQUIRE(parser.tags.size() == 1);
  CHECK(parser.tags[0]->EncodeLen() == 5);
}

TEST_CASE("CASNTag EncodeLen for SEQUENCE with child", "[asn1][tag]") {
  // SEQUENCE { INTEGER 1 } → 30 03 02 01 01 = 5 bytes
  uint8_t raw[] = {0x30, 0x03, 0x02, 0x01, 0x01};
  ByteDynArray data(ByteArray(raw, sizeof(raw)));
  CASNParser parser;
  parser.Parse(data);
  REQUIRE(parser.tags.size() == 1);
  CHECK(parser.tags[0]->EncodeLen() == 5);
}

// ── CASNTag: ContentLen
// ───────────────────────────────────────────────────────

TEST_CASE("CASNTag ContentLen returns value bytes only", "[asn1][tag]") {
  uint8_t raw[] = {0x04, 0x03, 0xAA, 0xBB, 0xCC};
  ByteDynArray data(ByteArray(raw, sizeof(raw)));
  CASNParser parser;
  parser.Parse(data);
  CHECK(parser.tags[0]->ContentLen() == 3);
}

// ── CASNTag: Encode
// ───────────────────────────────────────────────────────────

TEST_CASE("CASNTag Encode produces correct DER bytes", "[asn1][tag]") {
  uint8_t raw[] = {0x04, 0x02, 0x11, 0x22};
  ByteDynArray data(ByteArray(raw, sizeof(raw)));
  CASNParser parser;
  parser.Parse(data);

  ByteDynArray out(parser.tags[0]->EncodeLen());
  size_t len = 0;
  ByteArray outView(out);
  parser.tags[0]->Encode(outView, len);

  REQUIRE(len == 4);
  CHECK(out[0] == 0x04);
  CHECK(out[1] == 0x02);
  CHECK(out[2] == 0x11);
  CHECK(out[3] == 0x22);
}

// ── CASNTag: CheckTag
// ─────────────────────────────────────────────────────────

TEST_CASE("CASNTag CheckTag succeeds on matching tag", "[asn1][tag]") {
  uint8_t raw[] = {0x04, 0x01, 0xFF};
  ByteDynArray data(ByteArray(raw, sizeof(raw)));
  CASNParser parser;
  parser.Parse(data);
  // Should not throw
  CHECK_NOTHROW(parser.tags[0]->CheckTag(0x04));
}

TEST_CASE("CASNTag CheckTag throws on mismatched tag", "[asn1][tag]") {
  uint8_t raw[] = {0x04, 0x01, 0xFF};
  ByteDynArray data(ByteArray(raw, sizeof(raw)));
  CASNParser parser;
  parser.Parse(data);
  CHECK_THROWS(parser.tags[0]->CheckTag(0x02));
}

// ── CASNTag: Verify
// ───────────────────────────────────────────────────────────

TEST_CASE("CASNTag Verify succeeds when content matches", "[asn1][tag]") {
  uint8_t raw[] = {0x04, 0x03, 0xAA, 0xBB, 0xCC};
  ByteDynArray data(ByteArray(raw, sizeof(raw)));
  CASNParser parser;
  parser.Parse(data);

  uint8_t expected[] = {0xAA, 0xBB, 0xCC};
  ByteArray exp(expected, 3);
  CHECK_NOTHROW(parser.tags[0]->Verify(exp));
}

TEST_CASE("CASNTag Verify throws when content mismatches", "[asn1][tag]") {
  uint8_t raw[] = {0x04, 0x03, 0xAA, 0xBB, 0xCC};
  ByteDynArray data(ByteArray(raw, sizeof(raw)));
  CASNParser parser;
  parser.Parse(data);

  uint8_t wrong[] = {0xAA, 0xBB, 0xDD};
  ByteArray exp(wrong, 3);
  CHECK_THROWS(parser.tags[0]->Verify(exp));
}

// ── CASNTag: Child
// ────────────────────────────────────────────────────────────

TEST_CASE("CASNTag Child accesses nested tag by index and tag value",
          "[asn1][tag]") {
  // SEQUENCE { INTEGER 5 }
  uint8_t raw[] = {0x30, 0x03, 0x02, 0x01, 0x05};
  ByteDynArray data(ByteArray(raw, sizeof(raw)));
  CASNParser parser;
  parser.Parse(data);

  CASNTag &seq = *parser.tags[0];
  CASNTag &child = seq.Child(0, 0x02);
  CHECK(child.tagInt() == 0x02);
  CHECK(child.content[0] == 0x05);
}

TEST_CASE("CASNTag Child throws on wrong tag value", "[asn1][tag]") {
  uint8_t raw[] = {0x30, 0x03, 0x02, 0x01, 0x05};
  ByteDynArray data(ByteArray(raw, sizeof(raw)));
  CASNParser parser;
  parser.Parse(data);

  CASNTag &seq = *parser.tags[0];
  CHECK_THROWS(seq.Child(0, 0x04));  // wrong expected tag
}

// ── CASNTag: Reparse
// ──────────────────────────────────────────────────────────

TEST_CASE("CASNTag Reparse discovers children from content", "[asn1][tag]") {
  // Build an OCTET STRING whose content is itself a valid TLV
  // 04 05 02 03 01 02 03  → OCTET STRING containing INTEGER {01 02 03}
  uint8_t raw[] = {0x04, 0x05, 0x02, 0x03, 0x01, 0x02, 0x03};
  ByteDynArray data(ByteArray(raw, sizeof(raw)));
  CASNParser parser;
  parser.Parse(data);

  REQUIRE(parser.tags.size() == 1);
  REQUIRE(parser.tags[0]->tags.empty());  // not a sequence, no children yet

  parser.tags[0]->Reparse();
  // After reparse, content is re-parsed as TLV children
  REQUIRE(parser.tags[0]->tags.size() == 1);
  CHECK(parser.tags[0]->tags[0]->tagInt() == 0x02);
}
