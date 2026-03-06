// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file asn1_octet_string.h
 * @brief ASN.1 OCTET STRING type (tag 0x04).
 *
 * Represents an arbitrary sequence of octets, commonly used in CMS/PKCS#7
 * for message digests, encrypted content, and other binary data fields.
 */

#pragma once

#include "asn1_object.h"

/**
 * @brief ASN.1 OCTET STRING (tag 0x04).
 *
 * Encapsulates an arbitrary byte string. Used in CMS structures for
 * digest values, encrypted content, and extension values.
 */
class CASN1OctetString : public CASN1Object {
 private:
  const static BYTE TAG;

 public:
  /**
   * @brief Constructs an OCTET STRING by reading from a BufferedReader.
   * @param reader The reader positioned at the OCTET STRING TLV.
   */
  CASN1OctetString(BufferedReader& reader);

  /**
   * @brief Constructs an OCTET STRING from a byte array.
   * @param bOctetString The byte array containing the octet data.
   */
  CASN1OctetString(const ByteDynArray& bOctetString);

  /**
   * @brief Constructs an OCTET STRING from a hex or ASCII string.
   * @param szOctetString Null-terminated string to encode.
   */
  CASN1OctetString(const char* szOctetString);

  /**
   * @brief Constructs an OCTET STRING from a generic ASN.1 object.
   * @param octetString The ASN.1 object to reinterpret as an OCTET STRING.
   */
  CASN1OctetString(const CASN1Object& octetString);

  /**
   * @brief Constructs an OCTET STRING from a raw byte buffer.
   * @param value Pointer to the octet data.
   * @param len   Length of the data in bytes.
   */
  CASN1OctetString(const BYTE* value, long len);

  ~CASN1OctetString();
};
