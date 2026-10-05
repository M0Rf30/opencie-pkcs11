// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later
#include <catch2/catch_test_macros.hpp>
#include <string>

#include "crypto/aes.h"
#include "crypto/base64.h"
#include "crypto/sha1.h"
#include "crypto/sha256.h"
#include "crypto/sha512.h"
#include "util/array.h"

// ── CAES: unaligned input rejection (CIE-CIPHER-001) ───────────────────────

TEST_CASE("CAES::RawDecode throws on non-block-aligned input",
          "[crypto][aes]") {
  uint8_t keyBuf[16] = {0};
  uint8_t ivBuf[16] = {0};
  CAES aes(ByteArray(keyBuf, 16), ByteArray(ivBuf, 16));
  uint8_t ciphertext[17] = {0};  // not a multiple of AES_BLOCK_SIZE
  CHECK_THROWS_AS(aes.RawDecode(ByteArray(ciphertext, sizeof(ciphertext))),
                  logged_error);
}

TEST_CASE(
    "CAES::Decode throws on non-block-aligned input instead of "
    "returning uninitialized bytes",
    "[crypto][aes]") {
  uint8_t keyBuf[16] = {0};
  uint8_t ivBuf[16] = {0};
  CAES aes(ByteArray(keyBuf, 16), ByteArray(ivBuf, 16));
  // Simulates a tampered/malformed SM response: not a multiple of the
  // block size and empty is also rejected (previously underflowed via
  // `data.size() - 1`).
  uint8_t ciphertext[5] = {0};
  CHECK_THROWS_AS(aes.Decode(ByteArray(ciphertext, sizeof(ciphertext))),
                  logged_error);
  ByteDynArray empty;
  CHECK_THROWS_AS(aes.Decode(empty), logged_error);
}

TEST_CASE("CAES RawEncode/RawDecode round-trip on aligned data",
          "[crypto][aes]") {
  uint8_t keyBuf[16];
  uint8_t ivBuf[16];
  for (int i = 0; i < 16; i++) {
    keyBuf[i] = static_cast<uint8_t>(i);
    ivBuf[i] = static_cast<uint8_t>(0xF0 + i);
  }
  CAES aes(ByteArray(keyBuf, 16), ByteArray(ivBuf, 16));
  uint8_t plaintext[32];
  for (int i = 0; i < 32; i++) plaintext[i] = static_cast<uint8_t>(i * 3);

  ByteDynArray ct = aes.RawEncode(ByteArray(plaintext, 32));
  REQUIRE(ct.size() == 32);

  CAES aes2(ByteArray(keyBuf, 16), ByteArray(ivBuf, 16));
  ByteDynArray pt = aes2.RawDecode(ct);
  REQUIRE(pt.size() == 32);
  for (int i = 0; i < 32; i++) CHECK(pt[i] == plaintext[i]);
}

// ── SHA-256
// ───────────────────────────────────────────────────────────────────

TEST_CASE("SHA256 empty input", "[crypto][sha256]") {
  // echo -n "" | sha256sum =>
  // e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  CSHA256 sha;
  ByteDynArray empty;
  ByteDynArray digest = sha.Digest(empty);
  REQUIRE(digest.size() == 32);
  CHECK(digest[0] == 0xe3);
  CHECK(digest[1] == 0xb0);
  CHECK(digest[31] == 0x55);
}

TEST_CASE("SHA256 known vector: 'abc'", "[crypto][sha256]") {
  // sha256("abc") =
  // ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
  CSHA256 sha;
  const uint8_t input[] = {'a', 'b', 'c'};
  ByteArray ba(input, 3);
  ByteDynArray digest = sha.Digest(ba);
  REQUIRE(digest.size() == 32);
  CHECK(digest[0] == 0xba);
  CHECK(digest[1] == 0x78);
  CHECK(digest[2] == 0x16);
  CHECK(digest[31] == 0xad);
}

TEST_CASE("SHA256 incremental matches single-shot", "[crypto][sha256]") {
  const uint8_t input[] = {'h', 'e', 'l', 'l', 'o'};
  ByteArray ba(input, 5);

  CSHA256 sha1;
  ByteDynArray oneshot = sha1.Digest(ba);

  CSHA256 sha2;
  sha2.Init();
  sha2.Update(ByteArray(input, 2));
  sha2.Update(ByteArray(input + 2, 3));
  ByteDynArray incremental = sha2.Final();

  REQUIRE(oneshot.size() == 32);
  REQUIRE(incremental.size() == 32);
  CHECK(oneshot == incremental);
}

// ── SHA-1
// ─────────────────────────────────────────────────────────────────────

TEST_CASE("SHA1 known vector: 'abc'", "[crypto][sha1]") {
  // sha1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
  CSHA1 sha;
  const uint8_t input[] = {'a', 'b', 'c'};
  ByteArray ba(input, 3);
  ByteDynArray digest = sha.Digest(ba);
  REQUIRE(digest.size() == 20);
  CHECK(digest[0] == 0xa9);
  CHECK(digest[1] == 0x99);
  CHECK(digest[19] == 0x9d);
}

TEST_CASE("SHA1 empty input", "[crypto][sha1]") {
  // sha1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709
  CSHA1 sha;
  ByteDynArray empty;
  ByteDynArray digest = sha.Digest(empty);
  REQUIRE(digest.size() == 20);
  CHECK(digest[0] == 0xda);
  CHECK(digest[19] == 0x09);
}

TEST_CASE("SHA1 incremental matches single-shot", "[crypto][sha1]") {
  const uint8_t input[] = {'t', 'e', 's', 't'};
  ByteArray ba(input, 4);

  CSHA1 sha1;
  ByteDynArray oneshot = sha1.Digest(ba);

  CSHA1 sha2;
  sha2.Init();
  sha2.Update(ByteArray(input, 2));
  sha2.Update(ByteArray(input + 2, 2));
  ByteDynArray incremental = sha2.Final();

  CHECK(oneshot == incremental);
}

// ── SHA-512
// ───────────────────────────────────────────────────────────────────

TEST_CASE("SHA512 known vector: 'abc'", "[crypto][sha512]") {
  // sha512("abc") starts with ddaf35a193617aba...
  CSHA512 sha;
  const uint8_t input[] = {'a', 'b', 'c'};
  ByteDynArray ba(ByteArray(input, 3));
  ByteDynArray digest = sha.Digest(ba);
  REQUIRE(digest.size() == 64);
  CHECK(digest[0] == 0xdd);
  CHECK(digest[1] == 0xaf);
  CHECK(digest[2] == 0x35);
}

// ── Base64
// ────────────────────────────────────────────────────────────────────

TEST_CASE("Base64 encode known value", "[crypto][base64]") {
  // base64("Man") = "TWFu"
  const uint8_t input[] = {'M', 'a', 'n'};
  ByteArray ba(input, 3);
  CBase64 b64;
  std::string encoded;
  b64.Encode(ba, encoded);
  CHECK(encoded == "TWFu");
}

TEST_CASE("Base64 decode known value", "[crypto][base64]") {
  CBase64 b64;
  ByteDynArray decoded;
  b64.Decode("TWFu", decoded);
  REQUIRE(decoded.size() == 3);
  CHECK(decoded[0] == 'M');
  CHECK(decoded[1] == 'a');
  CHECK(decoded[2] == 'n');
}

TEST_CASE("Base64 round-trip", "[crypto][base64]") {
  const uint8_t input[] = {0x00, 0x01, 0x02, 0xFE, 0xFF};
  ByteArray ba(input, 5);
  CBase64 b64;

  std::string encoded;
  b64.Encode(ba, encoded);

  ByteDynArray decoded;
  b64.Decode(encoded.c_str(), decoded);

  REQUIRE(decoded.size() == 5);
  for (size_t i = 0; i < 5; ++i) CHECK(decoded[i] == input[i]);
}

TEST_CASE("Base64 encode empty input", "[crypto][base64]") {
  ByteDynArray empty;
  CBase64 b64;
  std::string encoded;
  b64.Encode(empty, encoded);
  CHECK(encoded.empty());
}
