// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file asn1_integer.h
 * @brief ASN.1 INTEGER type (tag 0x02).
 *
 * Represents a signed integer of arbitrary size, used in CMS/PKCS#7
 * for version numbers, serial numbers, and RSA key components.
 */

#pragma once

#include "asn1_object.h"

/**
 * @brief ASN.1 INTEGER (tag 0x02).
 *
 * Encodes and decodes integer values in two's-complement DER form.
 * Handles both small values (fitting in a C++ int/long) and
 * arbitrary-precision values used in RSA keys and certificate
 * serial numbers.
 */
class CASN1Integer : public CASN1Object {
 private:
  static const BYTE TAG;

 public:
  /**
   * @brief Constructs an INTEGER from an unsigned long value.
   * @param val The integer value to encode.
   */
  CASN1Integer(unsigned long);

  /**
   * @brief Constructs an INTEGER from a generic ASN.1 object.
   * @param obj The ASN.1 object to reinterpret as an INTEGER.
   */
  CASN1Integer(const CASN1Object& obj);

  /**
   * @brief Constructs an INTEGER from a raw big-endian byte buffer.
   * @param pbtVal Pointer to the integer value bytes.
   * @param nLen   Length of the value in bytes.
   */
  CASN1Integer(const BYTE* pbtVal, unsigned int nLen);

  virtual ~CASN1Integer();

  /**
   * @brief Returns the integer value as a signed int.
   * @return The decoded value (truncated if larger than int range).
   */
  int getIntValue() const;

  /**
   * @brief Returns the integer value as an unsigned long.
   * @return The decoded value (truncated if larger than unsigned long range).
   */
  unsigned long getLongValue() const;
};
