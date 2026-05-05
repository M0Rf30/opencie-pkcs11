// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file asn1_bit_string.h
 * @brief ASN.1 BIT STRING primitive type.
 *
 * Represents an ASN.1 BIT STRING value (tag 0x03), used in X.509
 * certificates for public keys and signature values, and in various
 * other ASN.1 structures that carry bit-oriented data.
 */

#pragma once

#include "asn1_object.h"

/**
 * @brief ASN.1 BIT STRING (tag 0x03).
 *
 * Wraps a DER-encoded BIT STRING, handling the leading unused-bits
 * octet that precedes the actual bit data.
 */
class CASN1BitString : public CASN1Object {
 public:
  /**
   * @brief Parses a BIT STRING from a DER-encoded stream.
   * @param reader Buffered reader positioned at the BIT STRING TLV.
   */
  explicit CASN1BitString(BufferedReader& reader);

  /**
   * @brief Constructs a BIT STRING from an already-parsed ASN.1 object.
   * @param obj Generic ASN.1 object containing BIT STRING encoding.
   */
  explicit CASN1BitString(const CASN1Object& obj);

  virtual ~CASN1BitString() override;

 private:
  /** @brief DER tag byte for BIT STRING (0x03). */
  static const BYTE TAG;
};
