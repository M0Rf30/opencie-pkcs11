// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

/**
 * @file rsa_private_key.h
 * @brief PKCS#1 RSAPrivateKey ASN.1 structure.
 *
 * Represents an RSA private key in PKCS#1 format (RFC 8017 Appendix A.1.2),
 * containing the modulus, public exponent, and private exponent (plus
 * optional CRT parameters).
 *
 * @code
 * RSAPrivateKey ::= SEQUENCE {
 *     version           Version,
 *     modulus           INTEGER,  -- n
 *     publicExponent    INTEGER,  -- e
 *     privateExponent   INTEGER,  -- d
 *     prime1            INTEGER,  -- p
 *     prime2            INTEGER,  -- q
 *     exponent1         INTEGER,  -- d mod (p-1)
 *     exponent2         INTEGER,  -- d mod (q-1)
 *     coefficient       INTEGER,  -- (inverse of q) mod p
 *     otherPrimeInfos   OtherPrimeInfos OPTIONAL
 * }
 * @endcode
 */

#pragma once

#include "asn1/asn1_integer.h"
#include "asn1/asn1_sequence.h"
#include "asn1_object.h"

/**
 * @brief PKCS#1 RSAPrivateKey (RFC 8017 Appendix A.1.2).
 *
 * Provides construction from DER encoding, raw byte arrays, or explicit
 * key components, and accessors for the modulus, public exponent, and
 * private exponent.
 */
class CRSAPrivateKey : public CASN1Sequence {
 public:
  /**
   * @brief Parses an RSAPrivateKey from a DER-encoded stream.
   * @param reader Buffered reader positioned at the SEQUENCE.
   */
  CRSAPrivateKey(BufferedReader& reader);

  /**
   * @brief Constructs from an already-parsed ASN.1 object.
   * @param obj Generic ASN.1 object containing RSAPrivateKey encoding.
   */
  CRSAPrivateKey(const CASN1Object& obj);

  /**
   * @brief Constructs from a DER-encoded byte array.
   * @param content DER-encoded RSAPrivateKey bytes.
   */
  CRSAPrivateKey(const ByteDynArray& content);

  /**
   * @brief Constructs from modulus, public exponent, and private exponent.
   * @param modulus The RSA modulus (n).
   * @param pubExp  The public exponent (e).
   * @param priExp  The private exponent (d).
   */
  CRSAPrivateKey(const CASN1Integer& modulus, const CASN1Integer& pubExp,
                 const CASN1Integer& priExp);

  /**
   * @brief Constructs from a Microsoft-format RSA key blob.
   * @param pbtRSAKey_MS Pointer to the MS RSA key blob.
   * @param dwLen        Length of the key blob in bytes.
   */
  CRSAPrivateKey(const BYTE* pbtRSAKey_MS, const DWORD dwLen);

  virtual ~CRSAPrivateKey();

  /** @brief Returns the RSA modulus (n). */
  CASN1Integer getModulus();

  /** @brief Returns the public exponent (e). */
  CASN1Integer getPublicExponent();

  /** @brief Returns the private exponent (d). */
  CASN1Integer getPrivateExponent();
};
