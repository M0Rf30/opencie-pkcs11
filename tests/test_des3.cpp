// SPDX-License-Identifier: LGPL-3.0-or-later
#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <vector>

#include "crypto/des3.h"
#include "util/array.h"
#include "util/util_exception.h"

namespace {
std::vector<uint8_t> MakeKeyBuf(size_t len, uint8_t fill) {
  return std::vector<uint8_t>(len, fill);
}
}  // namespace

TEST_CASE("3DES 2-key raw encrypt/decrypt round trip", "[crypto][des3]") {
  std::vector<uint8_t> keyBuf = MakeKeyBuf(16, 0x11);
  ByteArray key(keyBuf.data(), keyBuf.size());  // 2-key 3DES
  std::vector<uint8_t> ivBuf = MakeKeyBuf(8, 0x22);
  ByteArray iv(ivBuf.data(), ivBuf.size());
  const uint8_t plain[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
  ByteArray data(plain, sizeof(plain));

  CDES3 enc(key, iv);
  ByteDynArray ct = enc.RawEncode(data);
  REQUIRE(ct.size() == sizeof(plain));

  CDES3 dec(key, iv);
  ByteDynArray pt = dec.RawDecode(ct);
  REQUIRE(pt.size() == sizeof(plain));
  for (size_t i = 0; i < sizeof(plain); ++i) CHECK(pt[i] == plain[i]);
}

TEST_CASE("3DES 3-key Encode/Decode with ISO padding round trip",
          "[crypto][des3]") {
  std::vector<uint8_t> keyBuf = MakeKeyBuf(24, 0xAA);
  ByteArray key(keyBuf.data(), keyBuf.size());  // 3-key 3DES
  std::vector<uint8_t> ivBuf = MakeKeyBuf(8, 0x00);
  ByteArray iv(ivBuf.data(), ivBuf.size());
  const uint8_t plain[] = {'h', 'e', 'l', 'l', 'o'};
  ByteArray data(plain, sizeof(plain));

  CDES3 enc(key, iv);
  ByteDynArray ct = enc.Encode(data);
  CHECK(ct.size() % DES_BLOCK_SIZE == 0);
  CHECK(ct.size() > sizeof(plain));

  CDES3 dec(key, iv);
  ByteDynArray pt = dec.Decode(ct);
  REQUIRE(pt.size() == sizeof(plain));
  for (size_t i = 0; i < sizeof(plain); ++i) CHECK(pt[i] == plain[i]);
}

TEST_CASE("3DES rejects single-DES 8-byte key", "[crypto][des3]") {
  std::vector<uint8_t> keyBuf = MakeKeyBuf(8, 0x01);
  ByteArray key(keyBuf.data(), keyBuf.size());  // rejected: single-DES length
  std::vector<uint8_t> ivBuf = MakeKeyBuf(8, 0x02);
  ByteArray iv(ivBuf.data(), ivBuf.size());
  CDES3 c;
  CHECK_THROWS_AS(c.Init(key, iv), logged_error);
}

TEST_CASE("3DES RawEncode rejects non-block-aligned input", "[crypto][des3]") {
  std::vector<uint8_t> keyBuf = MakeKeyBuf(16, 0x01);
  ByteArray key(keyBuf.data(), keyBuf.size());
  std::vector<uint8_t> ivBuf = MakeKeyBuf(8, 0x02);
  ByteArray iv(ivBuf.data(), ivBuf.size());
  const uint8_t plain[] = {0x01, 0x02, 0x03};
  ByteArray data(plain, sizeof(plain));

  CDES3 enc(key, iv);
  CHECK_THROWS_AS(enc.RawEncode(data), logged_error);
}
