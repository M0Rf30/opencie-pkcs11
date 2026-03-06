// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

/**
 * @file mac.cpp
 * @brief Implementation of Retail MAC (ISO 9797-1 Algorithm 3) for CIE secure
 * messaging.
 */

#include "crypto/mac.h"

#include <cryptopp/hmac.h>

#include <cstring>

extern CLog Log;

/**
 * @brief Initializes the MAC computation with the given key and IV.
 * @param key DES key (16 or 24 bytes). 8-byte single DES keys are rejected.
 * @param iv  8-byte initialization vector.
 * @throws logged_error If the key size is 8 (single DES) or invalid.
 */
void CMAC::Init(const ByteArray &key, const ByteArray &iv) {
  init_func long KeySize = key.size();

  switch (KeySize) {
    case 8:
      throw logged_error("Error in DES encryption");
      break;
    case 16:
    case 24:
      this->key = key;
      break;
    default:
      throw logged_error("Invalid MAC key size");
  }
  this->iv = iv;

  exit_func
}

/** @brief Destructor. */
CMAC::~CMAC(void) {}

/**
 * @brief Computes the Retail MAC (ISO 9797-1 Algorithm 3) of the given data.
 *
 * Implements a two-step MAC:
 *  - Step 1: Single-DES CBC over all blocks except the last (using K1).
 *  - Step 2: 3DES-CBC over the last block (using the full key K1|K2 or
 * K1|K2|K3).
 *
 * Single DES is emulated via 3DES-EDE with K1|K1|K1 to avoid the OpenSSL 3.x
 * legacy provider requirement.
 *
 * @param data Input data to compute the MAC over.
 * @return ByteDynArray containing the 8-byte MAC value.
 */
ByteDynArray CMAC::Mac(const ByteArray &data) {
  init_func

      ByteDynArray resp(8);

  uint8_t ivBuf[8];
  memcpy(ivBuf, iv.data(), 8);

  size_t ANSILen = ANSIPadLen(data.size());

  // Retail MAC (ISO 9797-1 Algorithm 3):
  // Step 1: Single-DES CBC over all blocks except the last, using K1
  // Step 2: 3DES-CBC over the last block, using K1|K2|K3
  //
  // EVP_des_cbc() (single DES) requires the legacy provider in OpenSSL 3.x.
  // To avoid legacy provider dependency, emulate single DES by using
  // EVP_des_ede3_cbc() with key = K1|K1|K1 (3DES-EDE with identical keys
  // reduces to single DES: E(K1, D(K1, E(K1, x))) = E(K1, x)).

  if (data.size() > 8) {
    // Build single-DES-equivalent key: K1|K1|K1 (24 bytes)
    uint8_t singleDesKey[24];
    memcpy(singleDesKey, key.data(), 8);
    memcpy(singleDesKey + 8, key.data(), 8);
    memcpy(singleDesKey + 16, key.data(), 8);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int rc = EVP_EncryptInit_ex(ctx, EVP_des_ede3_cbc(), nullptr, singleDesKey,
                                ivBuf);
    ER_ASSERT(rc == 1, "Error initializing MAC step 1");
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    ByteDynArray baOutTmp(ANSILen - 8);
    int outLen = 0;
    rc = EVP_EncryptUpdate(ctx, baOutTmp.data(), &outLen, data.data(),
                           static_cast<int>(ANSILen - 8));
    ER_ASSERT(rc == 1, "Error in MAC encryption step 1");

    int finalLen = 0;
    rc = EVP_EncryptFinal_ex(ctx, baOutTmp.data() + outLen, &finalLen);
    ER_ASSERT(rc == 1, "Error finalizing MAC step 1");
    outLen += finalLen;

    // The chained IV for step 2 is the last 8 bytes of ciphertext output
    memcpy(ivBuf, baOutTmp.data() + outLen - 8, 8);

    EVP_CIPHER_CTX_free(ctx);
  }

  // Step 2: 3DES-CBC encrypt the final block using full key
  {
    const EVP_CIPHER *cipher;
    ByteDynArray fullKey;

    if (key.size() == 16) {
      // 2-key 3DES: expand to 24 bytes as K1|K2|K1
      cipher = EVP_des_ede3_cbc();
      fullKey.resize(24);
      memcpy(fullKey.data(), key.data(), 16);
      memcpy(fullKey.data() + 16, key.data(), 8);
    } else {
      cipher = EVP_des_ede3_cbc();
      fullKey = key;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int rc = EVP_EncryptInit_ex(ctx, cipher, nullptr, fullKey.data(), ivBuf);
    ER_ASSERT(rc == 1, "Error initializing MAC step 2");
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    size_t remaining = (data.size() - ANSILen) + 8;
    uint8_t dest[8];
    int outLen = 0;
    rc = EVP_EncryptUpdate(ctx, dest, &outLen, data.mid(ANSILen - 8).data(),
                           static_cast<int>(remaining));
    ER_ASSERT(rc == 1, "Error in MAC encryption step 2");

    int finalLen = 0;
    rc = EVP_EncryptFinal_ex(ctx, dest + outLen, &finalLen);
    ER_ASSERT(rc == 1, "Error finalizing MAC step 2");

    EVP_CIPHER_CTX_free(ctx);

    resp.copy(ByteArray(dest, 8));
  }

  return resp;

  exit_func
}

/** @brief Default constructor. */
CMAC::CMAC() {}

/**
 * @brief Constructs a CMAC instance and initializes it with the given key and
 * IV.
 * @param key DES key (16 or 24 bytes).
 * @param iv  8-byte initialization vector.
 */
CMAC::CMAC(const ByteArray &key, const ByteArray &iv) { Init(key, iv); }
