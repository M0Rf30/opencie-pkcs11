// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file crypto_util.h
 * @brief AES-CBC encryption and decryption utilities using OpenSSL EVP.
 *
 * Provides symmetric AES-128-CBC encrypt/decrypt functions with a
 * SHA-1-derived key from the application encryption key.
 *
 * Every call to encrypt() generates a fresh random IV and prepends it to
 * the ciphertext, after a 4-byte "CIE1" magic header, so decrypt() can
 * recover it: magic(4) || iv(16) || AES-CBC ciphertext. Data written
 * before this header existed used an all-zero IV with no header; decrypt()
 * detects the absence of the magic header and falls back to that legacy
 * zero-IV behavior so previously cached files keep decrypting.
 *
 * Both functions are declared `inline` because this header is included
 * from more than one translation unit.
 */

#pragma once

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <cstring>
#include <string>

#include "keys.h"

/// 4-byte header identifying the random-IV ciphertext format produced by
/// encrypt(). Legacy ciphertext written before random IVs were introduced
/// never starts with this sequence.
inline constexpr char kCacheCryptoMagic[4] = {'C', 'I', 'E', '1'};

/// AES-128 key size in bytes.
inline constexpr size_t kAesKeyLength = 16;
/// AES block size in bytes (also the CBC IV size).
inline constexpr size_t kAesBlockSize = 16;

/**
 * @brief Encrypts a plaintext message using AES-128-CBC with a random IV.
 *
 * Derives the AES key by computing SHA-1 of the application encryption key
 * and using the first 16 bytes as the AES key. A fresh random IV is
 * generated on every call (via RAND_bytes) and prepended to the
 * ciphertext output, after a 4-byte "CIE1" magic header.
 *
 * @param message Input plaintext string to encrypt.
 * @param ciphertext Output string receiving the encrypted data, formatted
 *        as magic(4) || iv(16) || AES-CBC(message).
 * @return 0 on success, -1 if the OpenSSL EVP context could not be
 *         created or initialized.
 */
inline int encrypt(const std::string& message, std::string& ciphertext) {
  unsigned char key[kAesKeyLength];
  unsigned char iv[kAesBlockSize];
  memset(key, 0x00, sizeof(key));

  // Random IV, fresh on every call.
  if (RAND_bytes(iv, sizeof(iv)) != 1) {
    OPENSSL_cleanse(key, sizeof(key));
    return -1;
  }

  std::string enckey = ENCRYPTION_KEY;

  unsigned char digest[SHA_DIGEST_LENGTH];
  SHA1(reinterpret_cast<const unsigned char*>(enckey.c_str()), enckey.length(),
       digest);
  memcpy(key, digest, sizeof(key));

  //
  // Create Cipher Text
  //
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(digest, sizeof(digest));
    return -1;
  }
  if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key, iv) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(digest, sizeof(digest));
    return -1;
  }

  // message.length() + 1 to include the trailing NUL (matches the
  // pre-migration Crypto++ behavior).
  int inLen = static_cast<int>(message.length() + 1);
  int blockSize = EVP_CIPHER_block_size(EVP_aes_128_cbc());
  std::string encBuf(inLen + blockSize, '\0');
  int outLen = 0, finalLen = 0;
  EVP_EncryptUpdate(
      ctx, reinterpret_cast<unsigned char*>(encBuf.data()), &outLen,
      reinterpret_cast<const unsigned char*>(message.c_str()), inLen);
  EVP_EncryptFinal_ex(
      ctx, reinterpret_cast<unsigned char*>(encBuf.data()) + outLen, &finalLen);
  EVP_CIPHER_CTX_free(ctx);
  encBuf.resize(outLen + finalLen);

  // Prepend the magic header and IV so decrypt() can recover them.
  ciphertext = std::string(kCacheCryptoMagic, sizeof(kCacheCryptoMagic)) +
               std::string(reinterpret_cast<char*>(iv), sizeof(iv)) + encBuf;

  OPENSSL_cleanse(key, sizeof(key));
  OPENSSL_cleanse(digest, sizeof(digest));
  OPENSSL_cleanse(iv, sizeof(iv));
  return 0;
};

/**
 * @brief Decrypts ciphertext produced by encrypt().
 *
 * If the input starts with the 4-byte "CIE1" magic header, the following
 * 16 bytes are read as the IV used for that message and the remainder is
 * the AES-CBC ciphertext. Otherwise the whole input is treated as legacy
 * zero-IV ciphertext, preserving backward compatibility with cache files
 * written before random IVs were introduced.
 *
 * @param ciphertext Input encrypted data string.
 * @param message Output string receiving the decrypted plaintext.
 * @return 0 on success, non-zero if ciphertext is too short to be valid
 *         or if OpenSSL fails to initialize/finalize the cipher.
 */
inline int decrypt(const std::string& ciphertext, std::string& message) {
  unsigned char key[kAesKeyLength];
  unsigned char iv[kAesBlockSize];
  memset(iv, 0x00, sizeof(iv));

  const size_t headerLen = sizeof(kCacheCryptoMagic) + sizeof(iv);
  std::string body;
  if (ciphertext.size() >= headerLen &&
      ciphertext.compare(0, sizeof(kCacheCryptoMagic), kCacheCryptoMagic,
                         sizeof(kCacheCryptoMagic)) == 0) {
    memcpy(iv, ciphertext.data() + sizeof(kCacheCryptoMagic), sizeof(iv));
    body = ciphertext.substr(headerLen);
  } else {
    // Legacy format: no magic header, all-zero IV, whole buffer is
    // ciphertext.
    body = ciphertext;
  }

  // A valid AES-CBC ciphertext is never shorter than one block.
  if (body.size() < kAesBlockSize) return 1;

  std::string enckey = ENCRYPTION_KEY;

  unsigned char digest[SHA_DIGEST_LENGTH];
  SHA1(reinterpret_cast<const unsigned char*>(enckey.c_str()), enckey.length(),
       digest);
  memcpy(key, digest, sizeof(key));

  // Decrypt
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(digest, sizeof(digest));
    return 1;
  }
  if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key, iv) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(digest, sizeof(digest));
    return 1;
  }

  int blockSize = EVP_CIPHER_block_size(EVP_aes_128_cbc());
  std::string decBuf(body.size() + blockSize, '\0');
  int outLen = 0, finalLen = 0;
  if (EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(decBuf.data()),
                        &outLen,
                        reinterpret_cast<const unsigned char*>(body.c_str()),
                        static_cast<int>(body.size())) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(digest, sizeof(digest));
    return 1;
  }
  if (EVP_DecryptFinal_ex(
          ctx, reinterpret_cast<unsigned char*>(decBuf.data()) + outLen,
          &finalLen) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(digest, sizeof(digest));
    return 1;
  }
  EVP_CIPHER_CTX_free(ctx);
  decBuf.resize(outLen + finalLen);
  message = decBuf;

  OPENSSL_cleanse(key, sizeof(key));
  OPENSSL_cleanse(digest, sizeof(digest));
  return 0;
};
