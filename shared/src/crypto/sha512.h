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
 public:
  /** @brief Constructs a new CSHA512 instance. */
  CSHA512() = default;

  /** @brief Destructor. */
  ~CSHA512() = default;

  CSHA512(const CSHA512&) = default;
  CSHA512& operator=(const CSHA512&) = default;

  /**
   * @brief Computes the SHA-512 digest of the given data in one shot.
   * @param data Input data to hash.
   * @return ByteDynArray containing the 64-byte SHA-512 digest.
   */
  static ByteDynArray Digest(const ByteArray& data);
};
