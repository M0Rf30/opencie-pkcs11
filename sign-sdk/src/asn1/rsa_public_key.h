// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

/**
 * @file rsa_public_key.h
 * @brief ASN.1 RSAPublicKey structure (modulus + public exponent).
 *
 * Implements the RSAPublicKey type defined in PKCS#1 (RFC 8017):
 *   RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
 *
 * Used within SubjectPublicKeyInfo in X.509 certificates carried
 * by CMS/PKCS#7 SignedData.
 */

#pragma once

#include "asn1/asn1_integer.h"
#include "asn1/asn1_sequence.h"
#include "asn1_object.h"

/**
 * @brief RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }.
 *
 * Encodes and decodes an RSA public key as defined in PKCS#1 / RFC 8017.
 */
class CRSAPublicKey : public CASN1Sequence {
 public:
  /**
   * @brief Constructs an RSAPublicKey by reading from a BufferedReader.
   * @param reader The reader positioned at the RSAPublicKey SEQUENCE TLV.
   */
  CRSAPublicKey(BufferedReader& reader);

  /**
   * @brief Constructs an RSAPublicKey from a generic ASN.1 object.
   * @param obj The ASN.1 object to reinterpret as an RSAPublicKey.
   */
  CRSAPublicKey(const CASN1Object& obj);

  /**
   * @brief Constructs an RSAPublicKey from modulus and exponent INTEGERs.
   * @param modulus  The RSA modulus (n).
   * @param exponent The RSA public exponent (e).
   */
  CRSAPublicKey(const CASN1Integer& modulus, const CASN1Integer& exponent);

  virtual ~CRSAPublicKey();

  /**
   * @brief Returns the RSA modulus (n).
   * @return The modulus as an ASN.1 INTEGER.
   */
  CASN1Integer getModulus();

  /**
   * @brief Returns the RSA public exponent (e).
   * @return The public exponent as an ASN.1 INTEGER.
   */
  CASN1Integer getExponent();

 private:
};
