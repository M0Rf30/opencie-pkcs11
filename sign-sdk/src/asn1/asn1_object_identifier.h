// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

/**
 * @file asn1_object_identifier.h
 * @brief ASN.1 OBJECT IDENTIFIER type (tag 0x06).
 *
 * Represents an OID used to identify algorithms, content types,
 * attributes, and other objects in CMS/PKCS#7 structures.
 */

#pragma once

#include <string>

#include "asn1_object.h"

/**
 * @brief ASN.1 OBJECT IDENTIFIER (tag 0x06).
 *
 * Encodes and decodes OIDs in the dotted-notation string form
 * (e.g., "1.2.840.113549.1.7.2" for id-signedData).
 */
class CASN1ObjectIdentifier : public CASN1Object {
 private:
  const static BYTE TAG;

 public:
  /**
   * @brief Constructs an OBJECT IDENTIFIER by reading from a BufferedReader.
   * @param reader The reader positioned at the OID TLV.
   */
  CASN1ObjectIdentifier(BufferedReader& reader);

  /**
   * @brief Constructs an OBJECT IDENTIFIER from a generic ASN.1 object.
   * @param obj The ASN.1 object to reinterpret as an OID.
   */
  CASN1ObjectIdentifier(const CASN1Object&);

  /**
   * @brief Constructs an OBJECT IDENTIFIER from a dotted OID string.
   * @param szObjId Null-terminated dotted OID string (e.g.,
   * "1.2.840.113549.1.1.1").
   */
  CASN1ObjectIdentifier(const char* szObjId);

  ~CASN1ObjectIdentifier();

  /**
   * @brief Converts the encoded OID value to its dotted-notation string form.
   * @param objId Output byte array receiving the OID string representation.
   */
  void ToOidString(ByteDynArray& objId);

  /**
   * @brief Compares this OID with another for equality.
   * @param objid The OBJECT IDENTIFIER to compare against.
   * @return True if both OIDs have identical encodings.
   */
  bool equals(const CASN1ObjectIdentifier& objid);
};
