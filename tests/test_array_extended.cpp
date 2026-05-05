// SPDX-License-Identifier: LGPL-3.0-or-later
#include <catch2/catch_test_macros.hpp>
#include <cstring>

#include "util/array.h"

// ── ByteArray: revmid
// ─────────────────────────────────────────────────────────

TEST_CASE("ByteArray revmid(toend) excludes last N bytes", "[array]") {
  uint8_t buf[] = {0x10, 0x20, 0x30, 0x40, 0x50};
  ByteArray ba(buf, 5);

  ByteArray r = ba.revmid(2);  // all except last 2 → {0x10, 0x20, 0x30}
  REQUIRE(r.size() == 3);
  CHECK(r[0] == 0x10);
  CHECK(r[2] == 0x30);
}

TEST_CASE("ByteArray revmid(toend, size) extracts window from end", "[array]") {
  uint8_t buf[] = {0x10, 0x20, 0x30, 0x40, 0x50};
  ByteArray ba(buf, 5);

  // 2 bytes, ending 1 from the end → bytes at index 2,3 = {0x30, 0x40}
  ByteArray r = ba.revmid(1, 2);
  REQUIRE(r.size() == 2);
  CHECK(r[0] == 0x30);
  CHECK(r[1] == 0x40);
}

// ── ByteArray: rightcopy
// ──────────────────────────────────────────────────────

TEST_CASE("ByteArray rightcopy places src at end of dst", "[array]") {
  uint8_t dst[5] = {0x00, 0x00, 0x00, 0x00, 0x00};
  uint8_t src[] = {0xAA, 0xBB};
  ByteArray bdst(dst, 5), bsrc(src, 2);
  bdst.rightcopy(bsrc);  // end=0 → src goes to last 2 bytes
  CHECK(dst[0] == 0x00);
  CHECK(dst[1] == 0x00);
  CHECK(dst[2] == 0x00);
  CHECK(dst[3] == 0xAA);
  CHECK(dst[4] == 0xBB);
}

TEST_CASE("ByteArray rightcopy with end offset", "[array]") {
  uint8_t dst[5] = {0x00, 0x00, 0x00, 0x00, 0x00};
  uint8_t src[] = {0xCC, 0xDD};
  ByteArray bdst(dst, 5), bsrc(src, 2);
  bdst.rightcopy(bsrc, 1);  // leave 1 byte free at right → bytes 2,3
  CHECK(dst[2] == 0xCC);
  CHECK(dst[3] == 0xDD);
  CHECK(dst[4] == 0x00);
}

// ── ByteArray: atoi
// ───────────────────────────────────────────────────────────

TEST_CASE("ByteArray atoi converts ASCII decimal bytes", "[array]") {
  const uint8_t raw[] = {'4', '2'};
  ByteArray ba(raw, 2);
  CHECK(ba.atoi() == 42);
}

TEST_CASE("ByteArray atoi single digit", "[array]") {
  const uint8_t raw[] = {'7'};
  ByteArray ba(raw, 1);
  CHECK(ba.atoi() == 7);
}

// ── ByteArray: comparison operators ──────────────────────────────────────────

TEST_CASE("ByteArray less-than comparison", "[array]") {
  uint8_t a[] = {0x01, 0x00};
  uint8_t b[] = {0x01, 0x01};
  ByteArray ba(a, 2), bb(b, 2);
  CHECK(ba < bb);
  CHECK(!(bb < ba));
}

TEST_CASE("ByteArray greater-than comparison", "[array]") {
  uint8_t a[] = {0xFF};
  uint8_t b[] = {0x01};
  ByteArray ba(a, 1), bb(b, 1);
  CHECK(ba > bb);
  CHECK(!(bb > ba));
}

// ── ByteArray: indexOf not found
// ──────────────────────────────────────────────

TEST_CASE("ByteArray indexOf returns false when not found", "[array]") {
  uint8_t haystack[] = {0x01, 0x02, 0x03};
  uint8_t needle[] = {0x04, 0x05};
  ByteArray ba(haystack, 3), nb(needle, 2);
  size_t pos = 0;
  CHECK(!ba.indexOf(nb, pos));
}

// ── ByteArray: getASN1Tag
// ─────────────────────────────────────────────────────

TEST_CASE("ByteArray getASN1Tag wraps content in TLV", "[array]") {
  uint8_t raw[] = {0xDE, 0xAD};
  ByteArray ba(raw, 2);
  ByteDynArray tagged = ba.getASN1Tag(0x04);
  // Expected: 04 02 DE AD
  REQUIRE(tagged.size() == 4);
  CHECK(tagged[0] == 0x04);
  CHECK(tagged[1] == 0x02);
  CHECK(tagged[2] == 0xDE);
  CHECK(tagged[3] == 0xAD);
}

// ── ByteDynArray: set() variadic
// ──────────────────────────────────────────────

TEST_CASE("ByteDynArray set() from single byte", "[array]") {
  ByteDynArray da;
  da.set((uint8_t)0x42);
  REQUIRE(da.size() == 1);
  CHECK(da[0] == 0x42);
}

TEST_CASE("ByteDynArray set() from hex string", "[array]") {
  // countHexData reads one hex char at a time and requires a space after each;
  // use single-char hex tokens separated by spaces
  ByteDynArray da;
  da.set(std::string("D E A D"));
  REQUIRE(da.size() == 4);
  CHECK(da[0] == 0x0D);
  CHECK(da[1] == 0x0E);
  CHECK(da[2] == 0x0A);
  CHECK(da[3] == 0x0D);
}

TEST_CASE("ByteDynArray set() from multiple parts", "[array]") {
  uint8_t raw[] = {0x01, 0x02};
  ByteArray ba(raw, 2);
  ByteDynArray da;
  da.set((uint8_t)0xAA, &ba, (uint8_t)0xBB);
  REQUIRE(da.size() == 4);
  CHECK(da[0] == 0xAA);
  CHECK(da[1] == 0x01);
  CHECK(da[2] == 0x02);
  CHECK(da[3] == 0xBB);
}

// ── ByteDynArray: detach
// ──────────────────────────────────────────────────────

TEST_CASE("ByteDynArray detach transfers ownership", "[array]") {
  ByteDynArray da(3);
  da[0] = 0x11;
  da[1] = 0x22;
  da[2] = 0x33;
  uint8_t *ptr = da.detach();
  REQUIRE(ptr != nullptr);
  CHECK(ptr[0] == 0x11);
  CHECK(ptr[2] == 0x33);
  CHECK(da.isNull());
  delete[] ptr;
}

// ── ByteDynArray: resize without keepData
// ─────────────────────────────────────

TEST_CASE("ByteDynArray resize without keepData changes size", "[array]") {
  ByteDynArray da(4);
  da[0] = 0xFF;
  da.resize(8, false);
  CHECK(da.size() == 8);
  // Data not guaranteed to be preserved — just check size
}

// ── ByteDynArray: setASN1Tag
// ──────────────────────────────────────────────────

TEST_CASE("ByteDynArray setASN1Tag stores TLV in self", "[array]") {
  uint8_t raw[] = {0x01, 0x02, 0x03};
  ByteArray content(raw, 3);
  ByteDynArray da;
  da.setASN1Tag(0x04, content);
  // Expected: 04 03 01 02 03
  REQUIRE(da.size() == 5);
  CHECK(da[0] == 0x04);
  CHECK(da[1] == 0x03);
  CHECK(da[2] == 0x01);
}

// ── ASN1TLength / ASN1LLength
// ─────────────────────────────────────────────────

TEST_CASE("ASN1TLength returns 1 for single-byte tags", "[array][asn1]") {
  CHECK(ASN1TLength(0x04) == 1);
  CHECK(ASN1TLength(0x30) == 1);
}

TEST_CASE("ASN1LLength returns 1 for short-form lengths", "[array][asn1]") {
  CHECK(ASN1LLength(0) == 1);
  CHECK(ASN1LLength(127) == 1);
}

TEST_CASE("ASN1LLength returns 2 for 1-byte long-form lengths",
          "[array][asn1]") {
  CHECK(ASN1LLength(128) == 2);
  CHECK(ASN1LLength(255) == 2);
}

TEST_CASE("ASN1LLength returns 3 for 2-byte long-form lengths",
          "[array][asn1]") {
  CHECK(ASN1LLength(256) == 3);
  CHECK(ASN1LLength(65535) == 3);
}
