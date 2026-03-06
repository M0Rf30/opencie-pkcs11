// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file sha256.h
 * @brief SHA-256 cryptographic hash wrapper using OpenSSL EVP interface.
 */

#pragma once

#include <openssl/evp.h>
#include <openssl/sha.h>

#include "util/array.h"

/**
 * @brief Wrapper class for SHA-256 hash computation using OpenSSL.
 *
 * Provides both single-shot and incremental (Init/Update/Final) hashing.
 */
class CSHA256 {
  bool isInit;      ///< Whether the hash context has been initialized.
  EVP_MD_CTX* ctx;  ///< OpenSSL EVP message digest context.

 public:
  /** @brief Constructs a new CSHA256 instance. */
  CSHA256();

  /** @brief Destructor; frees the EVP context. */
  ~CSHA256();

  /**
   * @brief Computes the SHA-256 digest of the given data in one shot.
   * @param data Input data to hash.
   * @return ByteDynArray containing the 32-byte SHA-256 digest.
   */
  ByteDynArray Digest(ByteArray& data);

  /** @brief Initializes the hash context for incremental hashing. */
  void Init();

  /**
   * @brief Feeds data into the incremental hash computation.
   * @param data Input data chunk to process.
   */
  void Update(ByteArray data);

  /**
   * @brief Finalizes the incremental hash and returns the digest.
   * @return ByteDynArray containing the 32-byte SHA-256 digest.
   */
  ByteDynArray Final();
};
