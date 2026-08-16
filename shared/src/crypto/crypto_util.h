// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file crypto_util.h
 * @brief Authenticated AES-CBC encryption/decryption for the local cache,
 *        using OpenSSL EVP.
 *
 * Provides symmetric AES-128-CBC encrypt/decrypt functions with a
 * SHA-1-derived key from the application encryption key, plus an
 * HMAC-SHA256 tag over the ciphertext so tampering is detected.
 *
 * Every call to encrypt() generates a fresh random IV, builds
 * magic(4) || iv(16) || AES-CBC ciphertext, and appends an HMAC-SHA256
 * tag (32 bytes) computed over that whole buffer with a key derived
 * independently from the AES key. decrypt() recomputes the tag with a
 * constant-time comparison and refuses to touch the ciphertext at all
 * unless it matches.
 *
 * There is no fallback path: any input that lacks the magic header or
 * fails the HMAC check is rejected outright, including cache files
 * written before this scheme existed (they carry no integrity
 * protection at all, so there is no way to tell a legitimate old file
 * from a forgery). Callers must treat a non-zero return as "no cached
 * data" and let the cache regenerate.
 *
 * Both functions are declared `inline` because this header is included
 * from more than one translation unit.
 */

#pragma once

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <cstring>
#include <string>

#include "keys.h"

/// 4-byte header identifying the authenticated ciphertext format produced
/// by encrypt(). Any input that does not start with this sequence is
/// rejected by decrypt() -- there is no legacy/unauthenticated fallback.
inline constexpr char kCacheCryptoMagic[4] = {'C', 'I', 'E', '1'};

/// AES-128 key size in bytes.
inline constexpr size_t kAesKeyLength = 16;
/// AES block size in bytes (also the CBC IV size).
inline constexpr size_t kAesBlockSize = 16;
/// HMAC-SHA256 key size in bytes.
inline constexpr size_t kHmacKeyLength = SHA256_DIGEST_LENGTH;
/// HMAC-SHA256 tag size in bytes.
inline constexpr size_t kHmacTagLength = SHA256_DIGEST_LENGTH;

/**
 * @brief Derives the AES encryption key and the HMAC integrity key from
 *        the application encryption key.
 *
 * The two keys are derived independently -- different hash algorithms
 * (SHA-1 vs SHA-256) over different domain-separated inputs -- so the
 * HMAC key is not simply a truncation or superset of the AES key.
 *
 * @param aesKey Output buffer of kAesKeyLength bytes.
 * @param macKey Output buffer of kHmacKeyLength bytes.
 */
inline void deriveCacheKeys(unsigned char* aesKey, unsigned char* macKey) {
  std::string enckey = ENCRYPTION_KEY;

  unsigned char digest[SHA_DIGEST_LENGTH];
  SHA1(reinterpret_cast<const unsigned char*>(enckey.c_str()), enckey.length(),
       digest);
  memcpy(aesKey, digest, kAesKeyLength);
  OPENSSL_cleanse(digest, sizeof(digest));

  std::string macKeyInput = enckey + "|cache-hmac-v1";
  SHA256(reinterpret_cast<const unsigned char*>(macKeyInput.c_str()),
         macKeyInput.length(), macKey);
}

/**
 * @brief Encrypts a plaintext message using AES-128-CBC with a random IV,
 *        authenticated with an HMAC-SHA256 tag.
 *
 * A fresh random IV is generated on every call (via RAND_bytes). The
 * output is magic(4) || iv(16) || AES-CBC(message) || HMAC-SHA256 tag(32),
 * where the tag authenticates everything before it.
 *
 * @param message Input plaintext string to encrypt.
 * @param ciphertext Output string receiving the encrypted data.
 * @return 0 on success, -1 if any OpenSSL operation (RNG, cipher context,
 *         encryption, or HMAC) fails.
 */
inline int encrypt(const std::string& message, std::string& ciphertext) {
  unsigned char key[kAesKeyLength];
  unsigned char macKey[kHmacKeyLength];
  unsigned char iv[kAesBlockSize];

  // Random IV, fresh on every call.
  if (RAND_bytes(iv, sizeof(iv)) != 1) {
    return -1;
  }

  deriveCacheKeys(key, macKey);

  //
  // Create Cipher Text
  //
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(macKey, sizeof(macKey));
    OPENSSL_cleanse(iv, sizeof(iv));
    return -1;
  }
  if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key, iv) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(macKey, sizeof(macKey));
    OPENSSL_cleanse(iv, sizeof(iv));
    return -1;
  }

  // message.length() + 1 to include the trailing NUL (matches the
  // pre-migration Crypto++ behavior).
  int inLen = static_cast<int>(message.length() + 1);
  int blockSize = EVP_CIPHER_block_size(EVP_aes_128_cbc());
  std::string encBuf(inLen + blockSize, '\0');
  int outLen = 0, finalLen = 0;
  if (EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(encBuf.data()),
                        &outLen,
                        reinterpret_cast<const unsigned char*>(message.c_str()),
                        inLen) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(macKey, sizeof(macKey));
    OPENSSL_cleanse(iv, sizeof(iv));
    return -1;
  }
  if (EVP_EncryptFinal_ex(
          ctx, reinterpret_cast<unsigned char*>(encBuf.data()) + outLen,
          &finalLen) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(macKey, sizeof(macKey));
    OPENSSL_cleanse(iv, sizeof(iv));
    return -1;
  }
  EVP_CIPHER_CTX_free(ctx);
  encBuf.resize(outLen + finalLen);

  // magic || iv || AES-CBC ciphertext: everything the HMAC tag below
  // authenticates.
  std::string body = std::string(kCacheCryptoMagic, sizeof(kCacheCryptoMagic)) +
                     std::string(reinterpret_cast<char*>(iv), sizeof(iv)) +
                     encBuf;

  unsigned char tag[kHmacTagLength];
  unsigned int tagLen = 0;
  if (HMAC(EVP_sha256(), macKey, static_cast<int>(kHmacKeyLength),
           reinterpret_cast<const unsigned char*>(body.data()), body.size(),
           tag, &tagLen) == nullptr ||
      tagLen != kHmacTagLength) {
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(macKey, sizeof(macKey));
    OPENSSL_cleanse(iv, sizeof(iv));
    return -1;
  }

  ciphertext = body + std::string(reinterpret_cast<char*>(tag), tagLen);

  OPENSSL_cleanse(key, sizeof(key));
  OPENSSL_cleanse(macKey, sizeof(macKey));
  OPENSSL_cleanse(iv, sizeof(iv));
  OPENSSL_cleanse(tag, sizeof(tag));
  return 0;
};

/**
 * @brief Decrypts and authenticates ciphertext produced by encrypt().
 *
 * The input must start with the 4-byte magic header followed by the
 * 16-byte IV, and must end with a 32-byte HMAC-SHA256 tag over
 * everything before it. The tag is verified with a constant-time
 * comparison before any ciphertext byte is decrypted; on any mismatch,
 * missing header, or undersized input, decryption is refused.
 *
 * @param ciphertext Input encrypted data string.
 * @param message Output string receiving the decrypted plaintext.
 * @return 0 on success, non-zero if the input is malformed, fails
 *         authentication, or OpenSSL fails to initialize/finalize the
 *         cipher.
 */
inline int decrypt(const std::string& ciphertext, std::string& message) {
  const size_t headerLen = sizeof(kCacheCryptoMagic) + kAesBlockSize;
  const size_t overhead = headerLen + kHmacTagLength;

  // Every blob produced by encrypt() carries the magic header, a fresh
  // IV, and a trailing HMAC tag authenticating both. Anything else --
  // including cache files written before this scheme existed, which
  // carry no integrity protection at all -- is indistinguishable from a
  // forgery and is rejected outright rather than trusted.
  if (ciphertext.size() < overhead ||
      ciphertext.compare(0, sizeof(kCacheCryptoMagic), kCacheCryptoMagic,
                         sizeof(kCacheCryptoMagic)) != 0) {
    return 1;
  }

  unsigned char iv[kAesBlockSize];
  memcpy(iv, ciphertext.data() + sizeof(kCacheCryptoMagic), sizeof(iv));

  // body = magic || iv || AES-CBC ciphertext (everything the tag covers).
  std::string body = ciphertext.substr(0, ciphertext.size() - kHmacTagLength);
  std::string tag = ciphertext.substr(ciphertext.size() - kHmacTagLength);
  std::string encBody = body.substr(headerLen);

  // A valid AES-CBC ciphertext is never shorter than one block.
  if (encBody.size() < kAesBlockSize) return 1;

  unsigned char key[kAesKeyLength];
  unsigned char macKey[kHmacKeyLength];
  deriveCacheKeys(key, macKey);

  unsigned char expectedTag[kHmacTagLength];
  unsigned int expectedTagLen = 0;
  if (HMAC(EVP_sha256(), macKey, static_cast<int>(kHmacKeyLength),
           reinterpret_cast<const unsigned char*>(body.data()), body.size(),
           expectedTag, &expectedTagLen) == nullptr ||
      expectedTagLen != kHmacTagLength) {
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(macKey, sizeof(macKey));
    return 1;
  }

  bool tagOk = CRYPTO_memcmp(expectedTag, tag.data(), kHmacTagLength) == 0;
  OPENSSL_cleanse(macKey, sizeof(macKey));
  OPENSSL_cleanse(expectedTag, sizeof(expectedTag));
  if (!tagOk) {
    OPENSSL_cleanse(key, sizeof(key));
    return 1;
  }

  // Decrypt
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    OPENSSL_cleanse(key, sizeof(key));
    return 1;
  }
  if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key, iv) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(key, sizeof(key));
    return 1;
  }

  int blockSize = EVP_CIPHER_block_size(EVP_aes_128_cbc());
  std::string decBuf(encBody.size() + blockSize, '\0');
  int outLen = 0, finalLen = 0;
  if (EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(decBuf.data()),
                        &outLen,
                        reinterpret_cast<const unsigned char*>(encBody.c_str()),
                        static_cast<int>(encBody.size())) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(key, sizeof(key));
    return 1;
  }
  if (EVP_DecryptFinal_ex(
          ctx, reinterpret_cast<unsigned char*>(decBuf.data()) + outLen,
          &finalLen) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(key, sizeof(key));
    return 1;
  }
  EVP_CIPHER_CTX_free(ctx);
  decBuf.resize(outLen + finalLen);
  message = decBuf;

  OPENSSL_cleanse(key, sizeof(key));
  return 0;
};
