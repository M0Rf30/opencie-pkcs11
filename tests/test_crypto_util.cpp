// SPDX-License-Identifier: LGPL-3.0-or-later
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <cryptopp/sha.h>

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
  CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH];
  CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];
  memset(iv, 0x00, sizeof(iv));

  std::string enckey = ENCRYPTION_KEY;
  CryptoPP::byte digest[CryptoPP::SHA1::DIGESTSIZE];
  CryptoPP::SHA1().CalculateDigest(
      digest, reinterpret_cast<const CryptoPP::byte*>(enckey.c_str()),
      enckey.length());
  memcpy(key, digest, sizeof(key));

  CryptoPP::AES::Encryption aesEncryption(key, sizeof(key));
  CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption,
                                                              iv);
  std::string ciphertext;
  CryptoPP::StreamTransformationFilter stf(
      cbcEncryption, new CryptoPP::StringSink(ciphertext));
  stf.Put(reinterpret_cast<const unsigned char*>(message.data()),
          message.size());
  stf.MessageEnd();
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

TEST_CASE("decrypt falls back to the legacy zero-IV format for old cache files",
          "[crypto][cache]") {
  std::string legacyPlaintext = "legacy cached PIN";
  std::string legacyCiphertext = LegacyZeroIvEncrypt(legacyPlaintext);

  // Sanity check: legacy ciphertext never carries the "CIE1" header.
  REQUIRE(legacyCiphertext.substr(0, 4) != "CIE1");

  std::string decrypted;
  REQUIRE(decrypt(legacyCiphertext, decrypted) == 0);
  CHECK(decrypted == legacyPlaintext);
}

TEST_CASE("decrypt rejects ciphertext shorter than one AES block",
          "[crypto][cache]") {
  std::string tooShort = "short";  // 5 bytes < AES::BLOCKSIZE (16)
  std::string decrypted;
  CHECK(decrypt(tooShort, decrypted) != 0);

  std::string empty;
  CHECK(decrypt(empty, decrypted) != 0);
}
