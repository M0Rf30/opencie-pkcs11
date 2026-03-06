// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file sha512.h
 * @brief SHA-512 cryptographic hash wrapper using OpenSSL EVP interface.
 */

#pragma once

#include <openssl/evp.h>

#include "util/array.h"

#define SHA512_DIGEST_LENGTH 64

/**
 * @brief Wrapper class for SHA-512 hash computation using OpenSSL.
 *
 * Provides a single-shot Digest() interface; Init/Update/Final are private.
 */
class CSHA512 {
  bool isInit;      ///< Whether the hash context has been initialized.
  EVP_MD_CTX *ctx;  ///< OpenSSL EVP message digest context.

  /** @brief Initializes the hash context. */
  void Init();

  /**
   * @brief Feeds data into the hash computation.
   * @param data Input data chunk to process.
   */
  void Update(ByteArray data);

  /**
   * @brief Finalizes the hash and returns the digest.
   * @return ByteDynArray containing the 64-byte SHA-512 digest.
   */
  ByteDynArray Final();

 public:
  /** @brief Constructs a new CSHA512 instance. */
  CSHA512();

  /** @brief Destructor; frees the EVP context. */
  ~CSHA512();

  /**
   * @brief Computes the SHA-512 digest of the given data in one shot.
   * @param data Input data to hash.
   * @return ByteDynArray containing the 64-byte SHA-512 digest.
   */
  ByteDynArray Digest(ByteArray &data);
};
