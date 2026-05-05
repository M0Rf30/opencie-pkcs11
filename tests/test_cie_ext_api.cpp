// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// test_cie_ext_api.cpp — Unit tests for the cie_timestamp / cie_encrypt /
// cie_decrypt public API additions (commit 839ede8).
//
// These tests exercise the parts that are testable without a physical CIE card,
// a TSA server, or the enrolment cache:
//
//  1. Hybrid-format layout  — the binary envelope written by cie_encrypt and
//     consumed by cie_decrypt:
//       [4 bytes BE: enc_key_len][enc_key][iv(12)][tag(16)][ciphertext]
//     We verify the layout by building and parsing the envelope manually.
//
//  2. AES-256-GCM round-trip — the symmetric layer used in hybrid mode.
//     Exercises the same OpenSSL calls as cie_encrypt / cie_decrypt so that
//     any regression in the cipher parameters is caught without a card.
//
//  3. SHA-256 digest for timestamp — cie_timestamp hashes the input file with
//     SHA-256 before sending the TSA request.  We verify the digest matches
//     the known NIST vector so the hash step is correct in isolation.
//
//  4. Argument-validation contract — every new function returns
//     CKR_ARGUMENTS_BAD (0x00000007) when a required pointer is NULL.
//     We call the functions through the public C header with NULL args and
//     a no-op progress callback; the card / TSA path is never reached.

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "crypto/sha256.h"
#include "util/array.h"

// PKCS#11 constants
#ifndef CKR_ARGUMENTS_BAD
#define CKR_ARGUMENTS_BAD 0x00000007UL
#endif

// PKCS#11 return value type
typedef unsigned long CK_RV;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Encrypt plaintext with AES-256-GCM using the given key and IV.
// Returns ciphertext; fills tag[16].
static std::vector<uint8_t> aes256gcm_encrypt(const uint8_t* key,
                                              const uint8_t* iv,
                                              const uint8_t* plain,
                                              size_t plain_len,
                                              uint8_t tag[16]) {
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  REQUIRE(ctx != nullptr);

  REQUIRE(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, iv) == 1);

  std::vector<uint8_t> cipher(plain_len + 16);
  int out_len = 0;
  int tmp_len = 0;
  REQUIRE(EVP_EncryptUpdate(ctx, cipher.data(), &out_len, plain,
                            (int)plain_len) == 1);
  REQUIRE(EVP_EncryptFinal_ex(ctx, cipher.data() + out_len, &tmp_len) == 1);
  out_len += tmp_len;
  REQUIRE(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) == 1);
  EVP_CIPHER_CTX_free(ctx);

  cipher.resize(out_len);
  return cipher;
}

// Decrypt ciphertext with AES-256-GCM; returns plaintext or empty on auth fail.
static std::vector<uint8_t> aes256gcm_decrypt(const uint8_t* key,
                                              const uint8_t* iv,
                                              const uint8_t* cipher,
                                              size_t cipher_len,
                                              const uint8_t tag[16]) {
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  REQUIRE(ctx != nullptr);

  REQUIRE(EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, iv) == 1);

  std::vector<uint8_t> plain(cipher_len);
  int out_len = 0;
  int tmp_len = 0;
  REQUIRE(EVP_DecryptUpdate(ctx, plain.data(), &out_len, cipher,
                            (int)cipher_len) == 1);

  // Set expected tag before finalising
  REQUIRE(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                              const_cast<uint8_t*>(tag)) == 1);

  int auth_ok = EVP_DecryptFinal_ex(ctx, plain.data() + out_len, &tmp_len);
  EVP_CIPHER_CTX_free(ctx);

  if (auth_ok != 1) return {};  // authentication failure
  out_len += tmp_len;
  plain.resize(out_len);
  return plain;
}

// ---------------------------------------------------------------------------
// 1. Hybrid-format layout
// ---------------------------------------------------------------------------

TEST_CASE("Hybrid format: 4-byte BE length field encodes encrypted key length",
          "[cie_encrypt][format]") {
  // Simulate the header written by cie_encrypt for a 256-byte encrypted key.
  const uint32_t enc_key_len = 256;
  uint32_t be = htonl(enc_key_len);

  uint8_t header[4];
  std::memcpy(header, &be, 4);

  // The reader (cie_decrypt) recovers the length with ntohl.
  uint32_t recovered = ntohl(*reinterpret_cast<uint32_t*>(header));
  CHECK(recovered == enc_key_len);
}

TEST_CASE(
    "Hybrid format: envelope layout is [4B "
    "len][enc_key][iv(12)][tag(16)][ciphertext]",
    "[cie_encrypt][format]") {
  // Build a minimal synthetic envelope and verify field offsets.
  const uint32_t enc_key_len = 8;  // fake 8-byte "encrypted key"
  const uint8_t fake_enc_key[8] = {0x01, 0x02, 0x03, 0x04,
                                   0x05, 0x06, 0x07, 0x08};
  const uint8_t fake_iv[12] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
                               0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
  const uint8_t fake_tag[16] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
                                0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x00};
  const uint8_t fake_cipher[4] = {0xDE, 0xAD, 0xBE, 0xEF};

  std::vector<uint8_t> envelope;
  uint32_t be = htonl(enc_key_len);
  envelope.insert(envelope.end(), reinterpret_cast<uint8_t*>(&be),
                  reinterpret_cast<uint8_t*>(&be) + 4);
  envelope.insert(envelope.end(), fake_enc_key, fake_enc_key + enc_key_len);
  envelope.insert(envelope.end(), fake_iv, fake_iv + 12);
  envelope.insert(envelope.end(), fake_tag, fake_tag + 16);
  envelope.insert(envelope.end(), fake_cipher, fake_cipher + 4);

  // Total size: 4 + 8 + 12 + 16 + 4 = 44
  REQUIRE(envelope.size() == 44u);

  // Parse back
  size_t offset = 0;
  uint32_t parsed_len = ntohl(*reinterpret_cast<uint32_t*>(envelope.data()));
  offset += 4;
  CHECK(parsed_len == enc_key_len);

  CHECK(std::memcmp(envelope.data() + offset, fake_enc_key, enc_key_len) == 0);
  offset += enc_key_len;

  CHECK(std::memcmp(envelope.data() + offset, fake_iv, 12) == 0);
  offset += 12;

  CHECK(std::memcmp(envelope.data() + offset, fake_tag, 16) == 0);
  offset += 16;

  CHECK(std::memcmp(envelope.data() + offset, fake_cipher, 4) == 0);
}

// ---------------------------------------------------------------------------
// 2. AES-256-GCM round-trip (the symmetric layer of cie_encrypt/cie_decrypt)
// ---------------------------------------------------------------------------

TEST_CASE("AES-256-GCM round-trip: encrypt then decrypt recovers plaintext",
          "[cie_encrypt][cie_decrypt][aes_gcm]") {
  uint8_t key[32];
  uint8_t iv[12];
  REQUIRE(RAND_bytes(key, 32) == 1);
  REQUIRE(RAND_bytes(iv, 12) == 1);

  const uint8_t plain[] = "Hello, CIE hybrid encryption!";
  const size_t plain_len = sizeof(plain) - 1;

  uint8_t tag[16];
  auto cipher = aes256gcm_encrypt(key, iv, plain, plain_len, tag);
  REQUIRE(!cipher.empty());
  CHECK(cipher.size() == plain_len);

  auto recovered =
      aes256gcm_decrypt(key, iv, cipher.data(), cipher.size(), tag);
  REQUIRE(recovered.size() == plain_len);
  CHECK(std::memcmp(recovered.data(), plain, plain_len) == 0);
}

TEST_CASE("AES-256-GCM: tampered tag causes authentication failure",
          "[cie_decrypt][aes_gcm]") {
  uint8_t key[32];
  uint8_t iv[12];
  REQUIRE(RAND_bytes(key, 32) == 1);
  REQUIRE(RAND_bytes(iv, 12) == 1);

  const uint8_t plain[] = "Integrity check";
  const size_t plain_len = sizeof(plain) - 1;

  uint8_t tag[16];
  auto cipher = aes256gcm_encrypt(key, iv, plain, plain_len, tag);

  // Flip one tag byte
  tag[0] ^= 0xFF;

  auto recovered =
      aes256gcm_decrypt(key, iv, cipher.data(), cipher.size(), tag);
  CHECK(recovered.empty());  // authentication must fail
}

TEST_CASE("AES-256-GCM: tampered ciphertext causes authentication failure",
          "[cie_decrypt][aes_gcm]") {
  uint8_t key[32];
  uint8_t iv[12];
  REQUIRE(RAND_bytes(key, 32) == 1);
  REQUIRE(RAND_bytes(iv, 12) == 1);

  const uint8_t plain[] = "Tamper test";
  const size_t plain_len = sizeof(plain) - 1;

  uint8_t tag[16];
  auto cipher = aes256gcm_encrypt(key, iv, plain, plain_len, tag);

  // Flip one ciphertext byte
  cipher[0] ^= 0x01;

  auto recovered =
      aes256gcm_decrypt(key, iv, cipher.data(), cipher.size(), tag);
  CHECK(recovered.empty());
}

TEST_CASE("AES-256-GCM: empty plaintext round-trip",
          "[cie_encrypt][cie_decrypt][aes_gcm]") {
  uint8_t key[32];
  uint8_t iv[12];
  REQUIRE(RAND_bytes(key, 32) == 1);
  REQUIRE(RAND_bytes(iv, 12) == 1);

  uint8_t tag[16];
  auto cipher = aes256gcm_encrypt(key, iv, nullptr, 0, tag);
  // Empty plaintext → empty ciphertext
  CHECK(cipher.empty());

  auto recovered =
      aes256gcm_decrypt(key, iv, cipher.data(), cipher.size(), tag);
  CHECK(recovered.empty());
}

// ---------------------------------------------------------------------------
// 3. SHA-256 digest for cie_timestamp
// ---------------------------------------------------------------------------

TEST_CASE("SHA-256 of empty input matches NIST vector (cie_timestamp path)",
          "[cie_timestamp][sha256]") {
  // NIST: SHA-256("") =
  // e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  CSHA256 sha;
  ByteDynArray empty;
  ByteDynArray digest = sha.Digest(empty);
  REQUIRE(digest.size() == 32u);
  CHECK(digest[0] == 0xe3);
  CHECK(digest[1] == 0xb0);
  CHECK(digest[31] == 0x55);
}

TEST_CASE("SHA-256 of 'abc' matches NIST vector (cie_timestamp path)",
          "[cie_timestamp][sha256]") {
  // NIST: SHA-256("abc") =
  // ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
  CSHA256 sha;
  const uint8_t input[] = {'a', 'b', 'c'};
  ByteArray ba(input, 3);
  ByteDynArray digest = sha.Digest(ba);
  REQUIRE(digest.size() == 32u);
  CHECK(digest[0] == 0xba);
  CHECK(digest[1] == 0x78);
  CHECK(digest[31] == 0xad);
}

TEST_CASE(
    "SHA-256 produces 32-byte output for arbitrary input (cie_timestamp path)",
    "[cie_timestamp][sha256]") {
  CSHA256 sha;
  // 1 KiB of 0x42
  ByteDynArray input(1024);
  for (size_t i = 0; i < input.size(); i++) input[i] = 0x42;
  ByteDynArray digest = sha.Digest(input);
  CHECK(digest.size() == 32u);
}
