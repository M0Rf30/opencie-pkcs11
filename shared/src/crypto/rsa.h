// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file rsa.h
 * @brief RSA public-key operations for CIE smart card authentication.
 */

#pragma once

#include <cryptopp/rsa.h>
#include <openssl/rsa.h>

#include "util/array.h"
#include "util/definitions.h"

/**
 * @brief RSA public-key wrapper using Crypto++ for CIE card verification.
 *
 * Supports raw RSA encryption (textbook RSA) and RSA-PSS signature
 * verification with SHA-512, as required by the CIE authentication protocol.
 */
class CRSA {
  CryptoPP::RSA::PublicKey pubKey;  ///< Crypto++ RSA public key object.

  /**
   * @brief Generates an RSA key pair (currently not supported).
   * @param size Key size in bits.
   * @param module Output modulus.
   * @param pubexp Output public exponent.
   * @param privexp Output private exponent.
   * @return Error code.
   * @throws logged_error Always; key generation is not implemented.
   */
  DWORD GenerateKey(DWORD size, ByteDynArray &module, ByteDynArray &pubexp,
                    ByteDynArray &privexp);

 public:
  /**
   * @brief Constructs an RSA object from a modulus and public exponent.
   * @param mod RSA modulus as a big-endian byte array.
   * @param exp RSA public exponent as a big-endian byte array.
   */
  CRSA(const ByteArray &mod, const ByteArray &exp);

  /** @brief Destructor. */
  ~CRSA(void);

  /**
   * @brief Performs raw (textbook) RSA public-key operation: data^e mod n.
   * @param data Input data to encrypt/verify (must be smaller than modulus).
   * @return ByteDynArray containing the RSA result.
   */
  ByteDynArray RSA_PURE(const ByteArray &data);

  /**
   * @brief Verifies an RSA-PSS signature using SHA-512.
   * @param signatureData The signature to verify.
   * @param toSign The original message that was signed.
   * @return true if the signature is valid, false otherwise.
   */
  bool RSA_PSS(const ByteArray &signatureData, const ByteArray &toSign);
};
