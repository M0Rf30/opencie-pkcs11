// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

/**
 * @file asn1_boolean.h
 * @brief ASN.1 BOOLEAN type (tag 0x01).
 *
 * Represents a DER-encoded BOOLEAN value, used in X.509 certificate
 * extensions (e.g., the critical flag) within CMS/PKCS#7 structures.
 */

#pragma once

#include "asn1/asn1_object.h"
#include "asn1/buffered_reader.h"

/**
 * @brief ASN.1 BOOLEAN (tag 0x01).
 *
 * Stores a single boolean value encoded per DER rules (0x00 for FALSE,
 * 0xFF for TRUE).
 */
class CASN1Boolean : public CASN1Object {
 private:
  static const BYTE TAG;

 public:
  /**
   * @brief Constructs a BOOLEAN with the given value.
   * @param val The boolean value (true or false).
   */
  CASN1Boolean(bool val);

  /**
   * @brief Constructs a BOOLEAN from a generic ASN.1 object.
   * @param obj The ASN.1 object to reinterpret as a BOOLEAN.
   */
  CASN1Boolean(const CASN1Object&);

  /**
   * @brief Constructs a BOOLEAN by reading from a BufferedReader.
   * @param reader The reader positioned at the BOOLEAN TLV.
   */
  CASN1Boolean(BufferedReader& reader);

  ~CASN1Boolean();

  /**
   * @brief Returns the decoded boolean value.
   * @return True if the encoded value is non-zero, false otherwise.
   */
  bool getBoolValue() const;
};
