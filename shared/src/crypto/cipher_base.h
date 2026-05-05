// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file cipher_base.h
 * @brief Common base class for EVP-based symmetric ciphers (AES, 3DES).
 *
 * Provides shared implementation for OpenSSL EVP cipher operations, eliminating
 * code duplication between AES and DES3 cipher classes. Handles the common
 * encrypt/decrypt workflow with configurable cipher selection and block size.
 */

#pragma once

#include <openssl/evp.h>

#include "util/util.h"
#include "util/util_exception.h"

/**
 * @brief Abstract base class for EVP-based symmetric ciphers.
 *
 * Provides common encryption/decryption logic for block ciphers using OpenSSL's
 * EVP interface. Derived classes (CAES, CDES3) implement cipher selection and
 * define cipher-specific constants.
 */
class CipherBase {
 protected:
  ByteDynArray key;
  ByteDynArray iv;

  /**
   * @brief Perform encryption or decryption operation.
   *
   * @param data Input data (plaintext for encryption, ciphertext for
   * decryption)
   * @param encOp Operation: 1 for encrypt, 0 for decrypt
   * @param cipher EVP cipher to use (AES-256-CBC, 3DES-EDE-CBC, etc.)
   * @param block_size Cipher block size in bytes (16 for AES, 8 for 3DES)
   * @return Processed data (ciphertext for encryption, plaintext for
   * decryption)
   */
  ByteDynArray perform_cipher_operation(const ByteArray &data, int encOp,
                                        const EVP_CIPHER *cipher,
                                        size_t block_size);

 public:
  /** @brief Default constructor. */
  CipherBase() = default;

  /** @brief Virtual destructor. */
  virtual ~CipherBase() = default;
};
