// SPDX-License-Identifier: LGPL-3.0-or-later
#include <openssl/evp.h>
#include <openssl/sha.h>

#include <catch2/catch_test_macros.hpp>
#include <cstring>
#include <string>

#include "crypto/crypto_util.h"
#include "keys.h"

namespace {
// Encrypts `message` the way the pre-hardening cache code did: AES-128-CBC,
// key = SHA1(ENCRYPTION_KEY), an all-zero IV, no magic header, no padding
// beyond PKCS#7. Used to simulate cache files written before random IVs
// and the "CIE1" header were introduced, so decrypt() backward
// compatibility can be verified against a realistic legacy ciphertext.
std::string LegacyZeroIvEncrypt(const std::string& message) {
  unsigned char key[16];
  unsigned char iv[16];
  memset(iv, 0x00, sizeof(iv));

  std::string enckey = ENCRYPTION_KEY;
  unsigned char digest[SHA_DIGEST_LENGTH];
  SHA1(reinterpret_cast<const unsigned char*>(enckey.c_str()), enckey.length(),
       digest);
  memcpy(key, digest, sizeof(key));

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key, iv);

  int inLen = static_cast<int>(message.size());
  int blockSize = EVP_CIPHER_block_size(EVP_aes_128_cbc());
  std::string ciphertext(inLen + blockSize, '\0');
  int outLen = 0, finalLen = 0;
  EVP_EncryptUpdate(
      ctx, reinterpret_cast<unsigned char*>(ciphertext.data()), &outLen,
      reinterpret_cast<const unsigned char*>(message.data()), inLen);
  EVP_EncryptFinal_ex(
      ctx, reinterpret_cast<unsigned char*>(ciphertext.data()) + outLen,
      &finalLen);
  EVP_CIPHER_CTX_free(ctx);
  ciphertext.resize(outLen + finalLen);
  return ciphertext;
}
}  // namespace

TEST_CASE("encrypt/decrypt round-trip recovers the original message",
          "[crypto][cache]") {
  std::string plaintext = "top secret PIN + certificate bytes";
  std::string ciphertext;
  REQUIRE(encrypt(plaintext, ciphertext) == 0);

  std::string decrypted;
  REQUIRE(decrypt(ciphertext, decrypted) == 0);

  // decrypt() also returns the trailing NUL that encrypt() appends.
  REQUIRE(decrypted.size() == plaintext.size() + 1);
  CHECK(decrypted.substr(0, plaintext.size()) == plaintext);
}

TEST_CASE("encrypt uses a random IV, not a fixed/zero one", "[crypto][cache]") {
  std::string plaintext = "same plaintext every time";
  std::string ciphertext1, ciphertext2;
  REQUIRE(encrypt(plaintext, ciphertext1) == 0);
  REQUIRE(encrypt(plaintext, ciphertext2) == 0);

  // Two encryptions of identical plaintext must differ (random IV per call).
  CHECK(ciphertext1 != ciphertext2);

  // Both must carry the "CIE1" magic header followed by a 16-byte IV.
  REQUIRE(ciphertext1.size() > 20);
  REQUIRE(ciphertext2.size() > 20);
  CHECK(ciphertext1.substr(0, 4) == "CIE1");
  CHECK(ciphertext2.substr(0, 4) == "CIE1");

  // The IVs themselves (bytes 4..20) must differ between calls.
  CHECK(ciphertext1.substr(4, 16) != ciphertext2.substr(4, 16));
}

TEST_CASE("decrypt rejects unauthenticated legacy zero-IV cache blobs",
          "[crypto][cache]") {
  std::string legacyPlaintext = "legacy cached PIN";
  std::string legacyCiphertext = LegacyZeroIvEncrypt(legacyPlaintext);

  // Sanity check: legacy ciphertext never carries the "CIE1" header.
  REQUIRE(legacyCiphertext.substr(0, 4) != "CIE1");

  // The legacy format carries no integrity tag, so an attacker with write
  // access to the cache file could forge a PIN or certificate. It is now
  // rejected outright; the cache regenerates from the card instead.
  std::string decrypted;
  CHECK(decrypt(legacyCiphertext, decrypted) != 0);
}

TEST_CASE("decrypt rejects a CIE1 blob whose HMAC tag was tampered with",
          "[crypto][cache]") {
  std::string plaintext = "authenticated cached PIN";
  std::string ciphertext;
  REQUIRE(encrypt(plaintext, ciphertext) == 0);

  std::string roundTripped;
  REQUIRE(decrypt(ciphertext, roundTripped) == 0);
  CHECK(roundTripped.substr(0, plaintext.size()) == plaintext);

  // Flipping any byte of the trailing tag must be detected.
  std::string tampered = ciphertext;
  tampered[tampered.size() - 1] ^= 0x01;
  std::string out;
  CHECK(decrypt(tampered, out) != 0);

  // So must flipping a byte of the ciphertext body.
  std::string tamperedBody = ciphertext;
  tamperedBody[tamperedBody.size() / 2] ^= 0x01;
  CHECK(decrypt(tamperedBody, out) != 0);
}

TEST_CASE("decrypt rejects ciphertext shorter than one AES block",
          "[crypto][cache]") {
  std::string tooShort = "short";  // 5 bytes < AES::BLOCKSIZE (16)
  std::string decrypted;
  CHECK(decrypt(tooShort, decrypted) != 0);

  std::string empty;
  CHECK(decrypt(empty, decrypted) != 0);
}
