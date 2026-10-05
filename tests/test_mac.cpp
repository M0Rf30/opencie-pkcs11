// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later
#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <vector>

#include "crypto/mac.h"
#include "util/array.h"
#include "util/util_exception.h"

namespace {
std::vector<uint8_t> MakeKeyBuf(size_t len, uint8_t fill) {
  return std::vector<uint8_t>(len, fill);
}
}  // namespace

TEST_CASE("Retail MAC output is 8 bytes and deterministic", "[crypto][mac]") {
  std::vector<uint8_t> keyBuf = MakeKeyBuf(16, 0x11);
  ByteArray key(keyBuf.data(), keyBuf.size());
  std::vector<uint8_t> ivBuf = MakeKeyBuf(8, 0x00);
  ByteArray iv(ivBuf.data(), ivBuf.size());
  const uint8_t data[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
  ByteArray ba(data, sizeof(data));

  CMAC mac1(key, iv);
  ByteDynArray out1 = mac1.Mac(ba);
  REQUIRE(out1.size() == 8);

  CMAC mac2(key, iv);
  ByteDynArray out2 = mac2.Mac(ba);
  REQUIRE(out2.size() == 8);

  CHECK(out1 == out2);
}

TEST_CASE("Retail MAC differs for different single-block inputs",
          "[crypto][mac]") {
  std::vector<uint8_t> keyBuf = MakeKeyBuf(16, 0x22);
  ByteArray key(keyBuf.data(), keyBuf.size());
  std::vector<uint8_t> ivBuf = MakeKeyBuf(8, 0x00);
  ByteArray iv(ivBuf.data(), ivBuf.size());
  const uint8_t data1[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
  const uint8_t data2[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x09};

  CMAC mac1(key, iv);
  ByteDynArray out1 = mac1.Mac(ByteArray(data1, sizeof(data1)));

  CMAC mac2(key, iv);
  ByteDynArray out2 = mac2.Mac(ByteArray(data2, sizeof(data2)));

  CHECK(out1 != out2);
}

TEST_CASE("Retail MAC handles multi-block input (>8 bytes)", "[crypto][mac]") {
  std::vector<uint8_t> keyBuf = MakeKeyBuf(24, 0x33);
  ByteArray key(keyBuf.data(), keyBuf.size());  // 3-key variant
  std::vector<uint8_t> ivBuf = MakeKeyBuf(8, 0x00);
  ByteArray iv(ivBuf.data(), ivBuf.size());
  const uint8_t data[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                          0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
  ByteArray ba(data, sizeof(data));

  CMAC mac(key, iv);
  ByteDynArray out = mac.Mac(ba);
  REQUIRE(out.size() == 8);
}

TEST_CASE("MAC rejects single-DES 8-byte key", "[crypto][mac]") {
  std::vector<uint8_t> keyBuf = MakeKeyBuf(8, 0x01);
  ByteArray key(keyBuf.data(), keyBuf.size());
  std::vector<uint8_t> ivBuf = MakeKeyBuf(8, 0x02);
  ByteArray iv(ivBuf.data(), ivBuf.size());
  CMAC m;
  CHECK_THROWS_AS(m.Init(key, iv), logged_error);
}

TEST_CASE("MAC rejects invalid key size", "[crypto][mac]") {
  std::vector<uint8_t> keyBuf = MakeKeyBuf(10, 0x01);
  ByteArray key(keyBuf.data(), keyBuf.size());
  std::vector<uint8_t> ivBuf = MakeKeyBuf(8, 0x02);
  ByteArray iv(ivBuf.data(), ivBuf.size());
  CMAC m;
  CHECK_THROWS_AS(m.Init(key, iv), logged_error);
}
