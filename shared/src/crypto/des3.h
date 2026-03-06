// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file des3.h
 * @brief Triple DES (3DES) CBC encryption and decryption wrapper using OpenSSL
 * EVP.
 *
 * Provides the CDES3 class for 3DES-CBC symmetric encryption/decryption with
 * support for 2-key (16-byte) and 3-key (24-byte) variants. Used in the CIE
 * PKCS#11 library for legacy secure-messaging and MAC computation with the
 * smart card.
 */

#pragma once

#include <openssl/evp.h>

#include "cipher_base.h"
#include "util/util.h"
#include "util/util_exception.h"

#define DESKEY_LENGTH 8  ///< Single DES key length in bytes (56-bit effective).
#define DES_BLOCK_SIZE 8  ///< 3DES cipher block size in bytes.
#define DES_ENCRYPT 1     ///< Operation flag for encryption.
#define DES_DECRYPT 0     ///< Operation flag for decryption.

/**
 * @brief Triple DES CBC symmetric cipher wrapper.
 *
 * Wraps OpenSSL's EVP interface for 3DES in CBC mode with no internal padding.
 * Supports 2-key (16-byte, EDE) and 3-key (24-byte, EDE3) Triple DES. Two
 * usage patterns are provided:
 *
 * - **Encode/Decode**: Automatically apply/remove ISO 7816-4 padding
 *   (via ISOPad / RemoveISOPad), suitable for arbitrary-length data.
 * - **RawEncode/RawDecode**: No padding; the caller must ensure the data
 *   length is a multiple of 8 bytes.
 *
 * 8-byte (single DES) keys are explicitly rejected.
 */
class CDES3 : public CipherBase {
  ByteDynArray Des3(const ByteArray &data, int encOp);

 public:
  /** @brief Default constructor. Key and IV must be set via Init(). */
  CDES3();

  /**
   * @brief Construct and initialize with a key and IV.
   * @param key 3DES key (16 bytes for 2-key or 24 bytes for 3-key).
   * @param iv  Initialization vector (must be 8 bytes).
   */
  CDES3(const ByteArray &key, const ByteArray &iv);

  /** @brief Destructor. */
  ~CDES3(void);

  /**
   * @brief Set (or reset) the 3DES key and initialization vector.
   * @param key 3DES key (16 or 24 bytes). 8-byte keys are rejected.
   * @param iv  Initialization vector (8 bytes).
   * @throws logged_error If the key size is 8 bytes or otherwise invalid.
   */
  void Init(const ByteArray &key, const ByteArray &iv);

  /**
   * @brief Encrypt data with automatic ISO 7816-4 padding.
   *
   * Applies ISOPad padding to @p data before 3DES-CBC encryption.
   *
   * @param data Plaintext of any length.
   * @return Ciphertext (length rounded up to next 8-byte multiple).
   */
  ByteDynArray Encode(const ByteArray &data);

  /**
   * @brief Decrypt data and remove ISO 7816-4 padding.
   *
   * Decrypts @p data with 3DES-CBC, then strips the ISO padding.
   *
   * @param data Ciphertext (must be a multiple of 8 bytes).
   * @return Plaintext with padding removed.
   */
  ByteDynArray Decode(const ByteArray &data);

  /**
   * @brief Encrypt data without padding (raw mode).
   *
   * The caller must ensure @p data length is a multiple of 8.
   *
   * @param data Plaintext (length must be a multiple of 8).
   * @return Ciphertext of the same length as input.
   * @throws logged_error If data length is not a multiple of 8.
   */
  ByteDynArray RawEncode(const ByteArray &data);

  /**
   * @brief Decrypt data without removing padding (raw mode).
   *
   * The caller must ensure @p data length is a multiple of 8.
   *
   * @param data Ciphertext (length must be a multiple of 8).
   * @return Plaintext of the same length as input.
   * @throws logged_error If data length is not a multiple of 8.
   */
  ByteDynArray RawDecode(const ByteArray &data);
};
