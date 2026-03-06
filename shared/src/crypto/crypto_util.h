// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

/**
 * @file crypto_util.h
 * @brief AES-CBC encryption and decryption utilities using Crypto++.
 *
 * Provides symmetric AES-128-CBC encrypt/decrypt functions with a
 * SHA-1-derived key from the application encryption key.
 */

#pragma once

#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <cryptopp/sha.h>

#include <string>

#include "keys.h"

/**
 * @brief Encrypts a plaintext message using AES-128-CBC.
 *
 * Derives the AES key by computing SHA-1 of the application encryption key
 * and using the first 16 bytes as the AES key. The IV is zero-filled.
 *
 * @param message Input plaintext string to encrypt.
 * @param ciphertext Output string receiving the encrypted data.
 * @return 0 on success.
 */
int encrypt(std::string& message, std::string& ciphertext) {
  CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH],
      iv[CryptoPP::AES::BLOCKSIZE];
  memset(key, 0x00, CryptoPP::AES::DEFAULT_KEYLENGTH);
  memset(iv, 0x00, CryptoPP::AES::BLOCKSIZE);

  std::string enckey = ENCRYPTION_KEY;

  CryptoPP::byte digest[CryptoPP::SHA1::DIGESTSIZE];
  CryptoPP::SHA1().CalculateDigest(digest, (CryptoPP::byte*)enckey.c_str(),
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

  return 0;
};

/**
 * @brief Decrypts ciphertext using AES-128-CBC.
 *
 * Derives the AES key by computing SHA-1 of the application encryption key
 * and using the first 16 bytes as the AES key. The IV is zero-filled.
 *
 * @param ciphertext Input encrypted data string.
 * @param message Output string receiving the decrypted plaintext.
 * @return 0 on success.
 */
int decrypt(std::string& ciphertext, std::string& message) {
  CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH],
      iv[CryptoPP::AES::BLOCKSIZE];
  memset(key, 0x00, CryptoPP::AES::DEFAULT_KEYLENGTH);
  memset(iv, 0x00, CryptoPP::AES::BLOCKSIZE);

  std::string enckey = ENCRYPTION_KEY;

  CryptoPP::byte digest[CryptoPP::SHA1::DIGESTSIZE];
  CryptoPP::SHA1().CalculateDigest(digest, (CryptoPP::byte*)enckey.c_str(),
                                   enckey.length());
  memcpy(key, digest, CryptoPP::AES::DEFAULT_KEYLENGTH);

  // Decrypt
  CryptoPP::AES::Decryption aesDecryption(key,
                                          CryptoPP::AES::DEFAULT_KEYLENGTH);
  CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption,
                                                              iv);

  CryptoPP::StreamTransformationFilter stfDecryptor(
      cbcDecryption, new CryptoPP::StringSink(message));
  stfDecryptor.Put(reinterpret_cast<const unsigned char*>(ciphertext.c_str()),
                   ciphertext.size());
  stfDecryptor.MessageEnd();

  return 0;
};
