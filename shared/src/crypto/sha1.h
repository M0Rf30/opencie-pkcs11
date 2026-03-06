// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

/**
 * @file sha1.h
 * @brief SHA-1 cryptographic hash wrapper using OpenSSL EVP interface.
 */

#pragma once
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "util/util.h"
#include "util/util_exception.h"

/**
 * @brief Wrapper class for SHA-1 hash computation using OpenSSL.
 *
 * Provides both single-shot and incremental (Init/Update/Final) hashing.
 * @note SHA-1 is considered cryptographically weak; prefer SHA-256 or SHA-512
 *       for new applications. This is retained for CIE protocol compatibility.
 */
class CSHA1 {
  bool isInit;      ///< Whether the hash context has been initialized.
  EVP_MD_CTX* ctx;  ///< OpenSSL EVP message digest context.

 public:
  /** @brief Constructs a new CSHA1 instance. */
  CSHA1();

  /** @brief Destructor; frees the EVP context. */
  ~CSHA1(void);

  /**
   * @brief Computes the SHA-1 digest of the given data in one shot.
   * @param data Input data to hash.
   * @return ByteDynArray containing the 20-byte SHA-1 digest.
   */
  ByteDynArray Digest(ByteArray data);

  /** @brief Initializes the hash context for incremental hashing. */
  void Init();

  /**
   * @brief Feeds data into the incremental hash computation.
   * @param data Input data chunk to process.
   */
  void Update(ByteArray data);

  /**
   * @brief Finalizes the incremental hash and returns the digest.
   * @return ByteDynArray containing the 20-byte SHA-1 digest.
   */
  ByteDynArray Final();
};
