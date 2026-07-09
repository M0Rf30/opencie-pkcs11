// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file crypto_util.h
 * @brief AES-CBC encryption and decryption utilities using Crypto++.
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

#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>
#include <openssl/crypto.h>

#include <cstring>
#include <string>

#include "keys.h"

/// 4-byte header identifying the random-IV ciphertext format produced by
/// encrypt(). Legacy ciphertext written before random IVs were introduced
/// never starts with this sequence.
inline constexpr char kCacheCryptoMagic[4] = {'C', 'I', 'E', '1'};

/**
 * @brief Encrypts a plaintext message using AES-128-CBC with a random IV.
 *
 * Derives the AES key by computing SHA-1 of the application encryption key
 * and using the first 16 bytes as the AES key. A fresh random IV is
 * generated on every call (via CryptoPP::AutoSeededRandomPool) and
 * prepended to the ciphertext output, after a 4-byte "CIE1" magic header.
 *
 * @param message Input plaintext string to encrypt.
 * @param ciphertext Output string receiving the encrypted data, formatted
 *        as magic(4) || iv(16) || AES-CBC(message).
 * @return 0 on success.
 */
inline int encrypt(const std::string& message, std::string& ciphertext) {
  CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH],
      iv[CryptoPP::AES::BLOCKSIZE];
  memset(key, 0x00, CryptoPP::AES::DEFAULT_KEYLENGTH);

  CryptoPP::AutoSeededRandomPool prng;
  prng.GenerateBlock(iv, sizeof(iv));

  std::string enckey = ENCRYPTION_KEY;

  CryptoPP::byte digest[CryptoPP::SHA1::DIGESTSIZE];
  CryptoPP::SHA1().CalculateDigest(
      digest, reinterpret_cast<const CryptoPP::byte*>(enckey.c_str()),
      enckey.length());
  memcpy(key, digest, CryptoPP::AES::DEFAULT_KEYLENGTH);
  //
  // Create Cipher Text
  //
  CryptoPP::AES::Encryption aesEncryption(key,
                                          CryptoPP::AES::DEFAULT_KEYLENGTH);
  CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption,
                                                              iv);

  CryptoPP::StreamTransformationFilter stfEncryptor(
      cbcEncryption, new CryptoPP::StringSink(ciphertext));
  stfEncryptor.Put(reinterpret_cast<const unsigned char*>(message.c_str()),
                   message.length() + 1);
  stfEncryptor.MessageEnd();

  // Prepend the magic header and IV so decrypt() can recover them.
  ciphertext = std::string(kCacheCryptoMagic, sizeof(kCacheCryptoMagic)) +
               std::string(reinterpret_cast<char*>(iv), sizeof(iv)) +
               ciphertext;

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
 * @return 0 on success, non-zero if ciphertext is too short to be valid.
 */
inline int decrypt(const std::string& ciphertext, std::string& message) {
  CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH],
      iv[CryptoPP::AES::BLOCKSIZE];
  memset(iv, 0x00, CryptoPP::AES::BLOCKSIZE);

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
  if (body.size() < CryptoPP::AES::BLOCKSIZE) return 1;

  std::string enckey = ENCRYPTION_KEY;

  CryptoPP::byte digest[CryptoPP::SHA1::DIGESTSIZE];
  CryptoPP::SHA1().CalculateDigest(
      digest, reinterpret_cast<const CryptoPP::byte*>(enckey.c_str()),
      enckey.length());
  memcpy(key, digest, CryptoPP::AES::DEFAULT_KEYLENGTH);

  // Decrypt
  CryptoPP::AES::Decryption aesDecryption(key,
                                          CryptoPP::AES::DEFAULT_KEYLENGTH);
  CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption,
                                                              iv);

  CryptoPP::StreamTransformationFilter stfDecryptor(
      cbcDecryption, new CryptoPP::StringSink(message));
  stfDecryptor.Put(reinterpret_cast<const unsigned char*>(body.c_str()),
                   body.size());
  stfDecryptor.MessageEnd();

  OPENSSL_cleanse(key, sizeof(key));
  OPENSSL_cleanse(digest, sizeof(digest));
  return 0;
};
