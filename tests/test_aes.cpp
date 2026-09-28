// SPDX-License-Identifier: LGPL-3.0-or-later
#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <vector>

#include "crypto/aes.h"
#include "util/array.h"
#include "util/util_exception.h"

namespace {
std::vector<uint8_t> MakeKeyBuf(size_t len, uint8_t fill) {
  return std::vector<uint8_t>(len, fill);
}
}  // namespace

TEST_CASE("AES-256 raw encrypt/decrypt round trip", "[crypto][aes]") {
  std::vector<uint8_t> keyBuf = MakeKeyBuf(32, 0x11);
  ByteArray key(keyBuf.data(), keyBuf.size());
  std::vector<uint8_t> ivBuf = MakeKeyBuf(16, 0x22);
  ByteArray iv(ivBuf.data(), ivBuf.size());
  const uint8_t plain[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                           0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
  ByteArray data(plain, sizeof(plain));

  CAES enc(key, iv);
  ByteDynArray ct = enc.RawEncode(data);
  REQUIRE(ct.size() == sizeof(plain));

  CAES dec(key, iv);
  ByteDynArray pt = dec.RawDecode(ct);
  REQUIRE(pt.size() == sizeof(plain));
  for (size_t i = 0; i < sizeof(plain); ++i) CHECK(pt[i] == plain[i]);
}

TEST_CASE("AES-128 Encode/Decode with ISO padding round trip",
          "[crypto][aes]") {
  std::vector<uint8_t> keyBuf = MakeKeyBuf(16, 0xAA);
  ByteArray key(keyBuf.data(), keyBuf.size());
  std::vector<uint8_t> ivBuf = MakeKeyBuf(16, 0x00);
  ByteArray iv(ivBuf.data(), ivBuf.size());
  const uint8_t plain[] = {'h', 'e', 'l', 'l', 'o'};
  ByteArray data(plain, sizeof(plain));

  CAES enc(key, iv);
  ByteDynArray ct = enc.Encode(data);
  // Ciphertext must be block-rounded and larger than the plaintext.
  CHECK(ct.size() % AES_BLOCK_SIZE == 0);
  CHECK(ct.size() > sizeof(plain));

  CAES dec(key, iv);
  ByteDynArray pt = dec.Decode(ct);
  REQUIRE(pt.size() == sizeof(plain));
  for (size_t i = 0; i < sizeof(plain); ++i) CHECK(pt[i] == plain[i]);
}

TEST_CASE("AES RawEncode rejects non-block-aligned input", "[crypto][aes]") {
  std::vector<uint8_t> keyBuf = MakeKeyBuf(32, 0x01);
  ByteArray key(keyBuf.data(), keyBuf.size());
  std::vector<uint8_t> ivBuf = MakeKeyBuf(16, 0x02);
  ByteArray iv(ivBuf.data(), ivBuf.size());
  const uint8_t plain[] = {0x01, 0x02, 0x03};
  ByteArray data(plain, sizeof(plain));

  CAES enc(key, iv);
  CHECK_THROWS_AS(enc.RawEncode(data), logged_error);
}

TEST_CASE("AES different keys produce different ciphertext", "[crypto][aes]") {
  std::vector<uint8_t> key1Buf = MakeKeyBuf(32, 0x01);
  ByteArray key1(key1Buf.data(), key1Buf.size());
  std::vector<uint8_t> key2Buf = MakeKeyBuf(32, 0x02);
  ByteArray key2(key2Buf.data(), key2Buf.size());
  std::vector<uint8_t> ivBuf = MakeKeyBuf(16, 0x00);
  ByteArray iv(ivBuf.data(), ivBuf.size());
  const uint8_t plain[] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
                           0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x00};
  ByteArray data(plain, sizeof(plain));

  CAES enc1(key1, iv);
  CAES enc2(key2, iv);
  ByteDynArray ct1 = enc1.RawEncode(data);
  ByteDynArray ct2 = enc2.RawEncode(data);
  CHECK(ct1 != ct2);
}
