// SPDX-License-Identifier: LGPL-3.0-or-later
#include <catch2/catch_test_macros.hpp>
#include <cstring>

#include "util/array.h"

// ── ByteArray ────────────────────────────────────────────────────────────────

TEST_CASE("ByteArray default construction is empty", "[array]") {
  ByteArray ba;
  CHECK(ba.isEmpty());
  CHECK(ba.isNull());
  CHECK(ba.size() == 0);
}

TEST_CASE("ByteArray view over buffer", "[array]") {
  uint8_t buf[] = {0x01, 0x02, 0x03, 0x04};
  ByteArray ba(buf, 4);

  CHECK(ba.size() == 4);
  CHECK(!ba.isEmpty());
  CHECK(!ba.isNull());
  CHECK(ba[0] == 0x01);
  CHECK(ba[3] == 0x04);
}

TEST_CASE("ByteArray bounds check throws", "[array]") {
  uint8_t buf[] = {0xAA};
  ByteArray ba(buf, 1);
  CHECK_THROWS(ba[1]);
}

TEST_CASE("ByteArray equality", "[array]") {
  uint8_t a[] = {1, 2, 3};
  uint8_t b[] = {1, 2, 3};
  uint8_t c[] = {1, 2, 4};
  ByteArray ba(a, 3), bb(b, 3), bc(c, 3);
  CHECK(ba == bb);
  CHECK(ba != bc);
}

TEST_CASE("ByteArray slicing: left/right/mid", "[array]") {
  uint8_t buf[] = {0x10, 0x20, 0x30, 0x40, 0x50};
  ByteArray ba(buf, 5);

  ByteArray l = ba.left(2);
  CHECK(l.size() == 2);
  CHECK(l[0] == 0x10);
  CHECK(l[1] == 0x20);

  ByteArray r = ba.right(2);
  CHECK(r.size() == 2);
  CHECK(r[0] == 0x40);
  CHECK(r[1] == 0x50);

  ByteArray m = ba.mid(1, 3);
  CHECK(m.size() == 3);
  CHECK(m[0] == 0x20);
  CHECK(m[2] == 0x40);

  ByteArray m2 = ba.mid(3);
  CHECK(m2.size() == 2);
  CHECK(m2[0] == 0x40);
}

TEST_CASE("ByteArray fill", "[array]") {
  uint8_t buf[4] = {};
  ByteArray ba(buf, 4);
  ba.fill(0xFF);
  for (size_t i = 0; i < 4; ++i) CHECK(ba[i] == 0xFF);
}

TEST_CASE("ByteArray reverse", "[array]") {
  uint8_t buf[] = {1, 2, 3, 4};
  ByteArray ba(buf, 4);
  ba.reverse();
  CHECK(ba[0] == 4);
  CHECK(ba[1] == 3);
  CHECK(ba[2] == 2);
  CHECK(ba[3] == 1);
}

TEST_CASE("ByteArray indexOf", "[array]") {
  uint8_t haystack[] = {0x00, 0x01, 0x02, 0x03, 0x04};
  uint8_t needle[] = {0x02, 0x03};
  ByteArray ba(haystack, 5);
  ByteArray nb(needle, 2);
  size_t pos = 0;
  CHECK(ba.indexOf(nb, pos));
  CHECK(pos == 2);
}

TEST_CASE("ByteArray copy", "[array]") {
  uint8_t src[] = {0xAA, 0xBB};
  uint8_t dst[4] = {0x00, 0x00, 0x00, 0x00};
  ByteArray bsrc(src, 2), bdst(dst, 4);
  bdst.copy(bsrc, 1);
  CHECK(dst[0] == 0x00);
  CHECK(dst[1] == 0xAA);
  CHECK(dst[2] == 0xBB);
  CHECK(dst[3] == 0x00);
}

// ── ByteDynArray ─────────────────────────────────────────────────────────────

TEST_CASE("ByteDynArray default construction", "[array]") {
  ByteDynArray da;
  CHECK(da.isEmpty());
  CHECK(da.isNull());
}

TEST_CASE("ByteDynArray sized construction", "[array]") {
  ByteDynArray da(8);
  CHECK(da.size() == 8);
  CHECK(!da.isNull());
}

TEST_CASE("ByteDynArray deep copy from ByteArray", "[array]") {
  uint8_t buf[] = {0x11, 0x22, 0x33};
  ByteArray ba(buf, 3);
  ByteDynArray da(ba);
  CHECK(da.size() == 3);
  CHECK(da[0] == 0x11);
  // Mutating original doesn't affect copy
  buf[0] = 0xFF;
  CHECK(da[0] == 0x11);
}

TEST_CASE("ByteDynArray copy constructor is deep", "[array]") {
  ByteDynArray a(3);
  a[0] = 1;
  a[1] = 2;
  a[2] = 3;
  ByteDynArray b(a);
  b[0] = 99;
  CHECK(a[0] == 1);
}

TEST_CASE("ByteDynArray move constructor", "[array]") {
  ByteDynArray a(3);
  a[0] = 7;
  ByteDynArray b(std::move(a));
  CHECK(b[0] == 7);
  CHECK(a.isNull());
}

TEST_CASE("ByteDynArray append", "[array]") {
  uint8_t buf[] = {0x01, 0x02};
  ByteArray ba(buf, 2);
  ByteDynArray da;
  da.append(ba);
  da.append(ba);
  CHECK(da.size() == 4);
  CHECK(da[0] == 0x01);
  CHECK(da[2] == 0x01);
}

TEST_CASE("ByteDynArray push", "[array]") {
  ByteDynArray da;
  da.push(0xAB);
  da.push(0xCD);
  CHECK(da.size() == 2);
  CHECK(da[0] == 0xAB);
  CHECK(da[1] == 0xCD);
}

TEST_CASE("ByteDynArray resize keeps data", "[array]") {
  ByteDynArray da(3);
  da[0] = 1;
  da[1] = 2;
  da[2] = 3;
  da.resize(5, true);
  CHECK(da.size() == 5);
  CHECK(da[0] == 1);
  CHECK(da[2] == 3);
}

TEST_CASE("ByteDynArray hex string construction", "[array]") {
  ByteDynArray da(std::string("01 02 03 FF"));
  CHECK(da.size() == 4);
  CHECK(da[0] == 0x01);
  CHECK(da[3] == 0xFF);
}

TEST_CASE("ByteDynArray clear", "[array]") {
  ByteDynArray da(4);
  da.clear();
  CHECK(da.isEmpty());
  CHECK(da.isNull());
}

TEST_CASE("readHexData utility", "[array]") {
  ByteDynArray ba;
  readHexData("DE AD BE EF", ba);
  CHECK(ba.size() == 4);
  CHECK(ba[0] == 0xDE);
  CHECK(ba[3] == 0xEF);
}
