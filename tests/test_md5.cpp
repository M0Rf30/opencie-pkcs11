// SPDX-License-Identifier: LGPL-3.0-or-later
#include <catch2/catch_test_macros.hpp>
#include <cstring>

#include "crypto/md5.h"
#include "util/array.h"
#include "util/util_exception.h"

// MD5("") = d41d8cd98f00b204e9800998ecf8427e
// MD5("abc") = 900150983cd24fb0d6963f7d28e17f72
// MD5("The quick brown fox jumps over the lazy dog")
//   = 9e107d9d372bb6826bd81d3542a419d6

TEST_CASE("MD5 digest is 16 bytes", "[crypto][md5]") {
  CMD5 md5;
  ByteDynArray empty;
  ByteDynArray digest = md5.Digest(empty);
  REQUIRE(digest.size() == 16);
}

TEST_CASE("MD5 empty input", "[crypto][md5]") {
  // d41d8cd98f00b204e9800998ecf8427e
  CMD5 md5;
  ByteDynArray empty;
  ByteDynArray digest = md5.Digest(empty);
  REQUIRE(digest.size() == 16);
  CHECK(digest[0] == 0xd4);
  CHECK(digest[1] == 0x1d);
  CHECK(digest[2] == 0x8c);
  CHECK(digest[3] == 0xd9);
  CHECK(digest[15] == 0x7e);
}

TEST_CASE("MD5 known vector: 'abc'", "[crypto][md5]") {
  // 900150983cd24fb0d6963f7d28e17f72
  CMD5 md5;
  const uint8_t input[] = {'a', 'b', 'c'};
  ByteArray ba(input, 3);
  ByteDynArray digest = md5.Digest(ba);
  REQUIRE(digest.size() == 16);
  CHECK(digest[0] == 0x90);
  CHECK(digest[1] == 0x01);
  CHECK(digest[2] == 0x50);
  CHECK(digest[15] == 0x72);
}

TEST_CASE("MD5 known vector: quick brown fox", "[crypto][md5]") {
  // 9e107d9d372bb6826bd81d3542a419d6
  CMD5 md5;
  const char* msg = "The quick brown fox jumps over the lazy dog";
  ByteArray ba(reinterpret_cast<const uint8_t*>(msg), strlen(msg));
  ByteDynArray digest = md5.Digest(ba);
  REQUIRE(digest.size() == 16);
  CHECK(digest[0] == 0x9e);
  CHECK(digest[1] == 0x10);
  CHECK(digest[2] == 0x7d);
  CHECK(digest[15] == 0xd6);
}

TEST_CASE("MD5 incremental matches single-shot", "[crypto][md5]") {
  const uint8_t input[] = {'h', 'e', 'l', 'l', 'o'};
  ByteArray ba(input, 5);

  CMD5 md5a;
  ByteDynArray oneshot = md5a.Digest(ba);

  CMD5 md5b;
  md5b.Init();
  md5b.Update(ByteArray(input, 2));
  md5b.Update(ByteArray(input + 2, 3));
  ByteDynArray incremental = md5b.Final();

  REQUIRE(oneshot.size() == 16);
  REQUIRE(incremental.size() == 16);
  CHECK(oneshot == incremental);
}

TEST_CASE("MD5 Update without Init throws", "[crypto][md5]") {
  CMD5 md5;
  const uint8_t buf[] = {0x01};
  ByteArray ba(buf, 1);
  REQUIRE_THROWS_AS(md5.Update(ba), logged_error);
}

TEST_CASE("MD5 Final without Init throws", "[crypto][md5]") {
  CMD5 md5;
  REQUIRE_THROWS_AS(md5.Final(), logged_error);
}
