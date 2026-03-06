// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file aes.cpp
 * @brief AES-CBC encryption/decryption implementation using OpenSSL EVP.
 *
 * Implements the CAES class methods. All encryption uses the EVP high-level
 * interface with CBC mode and zero-padding disabled (padding is handled
 * externally via ISO 7816-4 pad/unpad helpers).
 */

#include "crypto/aes.h"

#include <openssl/evp.h>

extern CLog Log;

/**
 * @brief Select the appropriate OpenSSL AES-CBC cipher for a given key length.
 * @param keyLen Key length in bytes (16, 24, or 32).
 * @return Pointer to the EVP_CIPHER, or nullptr if the key length is invalid.
 */
static const EVP_CIPHER *aes_cbc_cipher(size_t keyLen) {
  switch (keyLen) {
    case 16:
      return EVP_aes_128_cbc();
    case 24:
      return EVP_aes_192_cbc();
    case 32:
      return EVP_aes_256_cbc();
    default:
      return nullptr;
  }
}

ByteDynArray CAES::AES(const ByteArray &data, int encOp) {
  const EVP_CIPHER *cipher = aes_cbc_cipher(key.size());
  ER_ASSERT(cipher != nullptr, "Invalid AES key size");

  return perform_cipher_operation(data, encOp, cipher, AES_BLOCK_SIZE);
}
void CAES::Init(const ByteArray &key, const ByteArray &iv) {
  init_func this->iv = iv;
  this->key = key;

  exit_func
}

CAES::CAES() {}

CAES::~CAES(void) {}

CAES::CAES(const ByteArray &key, const ByteArray &iv) { Init(key, iv); }

ByteDynArray CAES::Encode(const ByteArray &data) {
  init_func return AES(ISOPad16(data), AES_ENCRYPT);
}

ByteDynArray CAES::RawEncode(const ByteArray &data) {
  init_func ER_ASSERT((data.size() % AES_BLOCK_SIZE) == 0,
                      "Data size to encrypt must be a multiple of 16");
  return AES(data, AES_ENCRYPT);
}

ByteDynArray CAES::Decode(const ByteArray &data) {
  init_func ByteDynArray result = AES(data, AES_DECRYPT);
  result.resize(RemoveISOPad(result), true);
  return result;
}

ByteDynArray CAES::RawDecode(const ByteArray &data) {
  init_func ER_ASSERT((data.size() % AES_BLOCK_SIZE) == 0,
                      "Data size to decrypt must be a multiple of 16");
  return AES(data, AES_DECRYPT);
}
