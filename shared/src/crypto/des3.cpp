// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

/**
 * @file des3.cpp
 * @brief Triple DES CBC encryption/decryption implementation using OpenSSL EVP.
 *
 * Implements the CDES3 class methods. Uses EVP_des_ede_cbc() for 2-key
 * (16-byte) and EVP_des_ede3_cbc() for 3-key (24-byte) Triple DES. Both ciphers
 * are available in OpenSSL 3.x default provider (no legacy provider required).
 * Internal padding is disabled; ISO 7816-4 padding is handled by the caller
 * or by the Encode/Decode wrappers.
 */

#include "crypto/des3.h"

#include <cryptopp/misc.h>
#include <openssl/evp.h>

extern CLog Log;

void CDES3::Init(const ByteArray &key, const ByteArray &iv) {
  init_func long KeySize = key.size();

  switch (KeySize) {
    case 8:
      throw logged_error("8-byte single DES key not supported");
      break;
    case 16:
    case 24:
      this->key = key;
      break;
    default:
      throw logged_error("Invalid 3DES key size");
  }
  this->iv = iv;

  exit_func
}

CDES3::~CDES3(void) {}

CDES3::CDES3() {}

ByteDynArray CDES3::Des3(const ByteArray &data, int encOp) {
  const EVP_CIPHER *cipher;
  if (key.size() == 16)
    cipher = EVP_des_ede_cbc();
  else
    cipher = EVP_des_ede3_cbc();

  return perform_cipher_operation(data, encOp, cipher, DES_BLOCK_SIZE);
}

CDES3::CDES3(const ByteArray &key, const ByteArray &iv) { Init(key, iv); }

ByteDynArray CDES3::Encode(const ByteArray &data) {
  init_func return Des3(ISOPad(data), DES_ENCRYPT);
}

ByteDynArray CDES3::RawEncode(const ByteArray &data) {
  init_func ByteDynArray result;
  ER_ASSERT((data.size() % 8) == 0,
            "Data size to encrypt must be a multiple of 8");

  return Des3(data, DES_ENCRYPT);
}

ByteDynArray CDES3::Decode(const ByteArray &data) {
  init_func auto result = Des3(data, DES_DECRYPT);
  result.resize(RemoveISOPad(result), true);
  return result;
}

ByteDynArray CDES3::RawDecode(const ByteArray &data) {
  init_func ByteDynArray result;
  ER_ASSERT((data.size() % 8) == 0,
            "Data size to decrypt must be a multiple of 8");

  return Des3(data, DES_DECRYPT);
}
