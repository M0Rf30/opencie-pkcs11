// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file aes.h
 * @brief AES-CBC encryption and decryption wrapper using OpenSSL EVP.
 *
 * Provides the CAES class for AES-CBC symmetric encryption/decryption with
 * support for 128-bit, 192-bit, and 256-bit keys. Used throughout the CIE
 * PKCS#11 library for secure-messaging session encryption with the smart card.
 */

#pragma once

#include <openssl/evp.h>

#include "cipher_base.h"
#include "util/util.h"
#include "util/util_exception.h"

#define AESKEY_LENGTH 32   ///< Default AES key length in bytes (256-bit).
#define AES_BLOCK_SIZE 16  ///< AES cipher block size in bytes.
#define AES_ENCRYPT 1      ///< Operation flag for encryption.
#define AES_DECRYPT 0      ///< Operation flag for decryption.

/**
 * @brief AES-CBC symmetric cipher wrapper.
 *
 * Wraps OpenSSL's EVP interface for AES in CBC mode with no padding.
 * Supports 128-bit, 192-bit, and 256-bit keys. Two usage patterns are
 * provided:
 *
 * - **Encode/Decode**: Automatically apply/remove ISO 7816-4 padding
 *   (via ISOPad16 / RemoveISOPad), suitable for arbitrary-length data.
 * - **RawEncode/RawDecode**: No padding; the caller must ensure the data
 *   length is a multiple of @ref AES_BLOCK_SIZE (16 bytes).
 *
 * Typical usage in the CIE protocol is to protect APDU command/response
 * data during the secure-messaging session.
 */
class CAES : public CipherBase {
  ByteDynArray AES(const ByteArray &data, int encOp);

 public:
  /** @brief Default constructor. Key and IV must be set via Init(). */
  CAES();

  /**
   * @brief Construct and initialize with a key and IV.
   * @param key AES key (16, 24, or 32 bytes for AES-128/192/256).
   * @param iv  Initialization vector (must be 16 bytes).
   */
  CAES(const ByteArray &key, const ByteArray &iv);

  /** @brief Destructor. */
  ~CAES(void) override;

  /**
   * @brief Set (or reset) the AES key and initialization vector.
   * @param key AES key (16, 24, or 32 bytes).
   * @param iv  Initialization vector (16 bytes).
   */
  void Init(const ByteArray &key, const ByteArray &iv);

  /**
   * @brief Encrypt data with automatic ISO 7816-4 padding.
   *
   * Applies ISOPad16 padding to @p data before AES-CBC encryption.
   *
   * @param data Plaintext of any length.
   * @return Ciphertext (length rounded up to next AES_BLOCK_SIZE multiple).
   */
  ByteDynArray Encode(const ByteArray &data);

  /**
   * @brief Decrypt data and remove ISO 7816-4 padding.
   *
   * Decrypts @p data with AES-CBC, then strips the ISO padding.
   *
   * @param data Ciphertext (must be a multiple of AES_BLOCK_SIZE).
   * @return Plaintext with padding removed.
   */
  ByteDynArray Decode(const ByteArray &data);

  /**
   * @brief Encrypt data without padding (raw mode).
   *
   * The caller must ensure @p data length is a multiple of AES_BLOCK_SIZE.
   *
   * @param data Plaintext (length must be a multiple of 16).
   * @return Ciphertext of the same length as input.
   * @throws logged_error If data length is not a multiple of 16.
   */
  ByteDynArray RawEncode(const ByteArray &data);

  /**
   * @brief Decrypt data without removing padding (raw mode).
   *
   * The caller must ensure @p data length is a multiple of AES_BLOCK_SIZE.
   *
   * @param data Ciphertext (length must be a multiple of 16).
   * @return Plaintext of the same length as input.
   * @throws logged_error If data length is not a multiple of 16.
   */
  ByteDynArray RawDecode(const ByteArray &data);
};
