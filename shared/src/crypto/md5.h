// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

/**
 * @file md5.h
 * @brief MD5 cryptographic hash wrapper using OpenSSL EVP interface.
 */

#pragma once

#include <openssl/evp.h>
#include <openssl/md5.h>

#include "util/util.h"
#include "util/util_exception.h"

/**
 * @brief Wrapper class for MD5 hash computation using OpenSSL.
 *
 * Provides both single-shot and incremental (Init/Update/Final) hashing.
 * @note MD5 is considered cryptographically broken; this is retained for
 *       CIE protocol compatibility only.
 */
class CMD5 {
  bool isInit;      ///< Whether the hash context has been initialized.
  EVP_MD_CTX* ctx;  ///< OpenSSL EVP message digest context.

 public:
  /** @brief Constructs a new CMD5 instance. */
  CMD5();

  /** @brief Destructor; frees the EVP context. */
  ~CMD5(void);

  /**
   * @brief Computes the MD5 digest of the given data in one shot.
   * @param data Input data to hash.
   * @return ByteDynArray containing the 16-byte MD5 digest.
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
   * @return ByteDynArray containing the 16-byte MD5 digest.
   */
  ByteDynArray Final();
};
