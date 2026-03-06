// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file asn1_sequence.h
 * @brief ASN.1 SEQUENCE container (tag 0x30).
 *
 * Provides an ordered collection of ASN.1 elements encoded with
 * the universal SEQUENCE tag. Used throughout CMS/PKCS#7 structures
 * for composite types such as AlgorithmIdentifier and Certificate.
 */

#pragma once

#include "asn1_generic_sequence.h"

/**
 * @brief ASN.1 SEQUENCE (tag 0x30) container.
 *
 * Specializes CASN1GenericSequence with the standard SEQUENCE tag.
 * Elements are accessed positionally and maintain their insertion order.
 */
class CASN1Sequence : public CASN1GenericSequence {
 public:
  ~CASN1Sequence();

  /** @brief Constructs an empty SEQUENCE. */
  CASN1Sequence();

  /**
   * @brief Constructs a SEQUENCE by decoding a DER byte array.
   * @param content DER-encoded SEQUENCE bytes.
   */
  CASN1Sequence(const ByteDynArray& content);

  /**
   * @brief Constructs a SEQUENCE by reading from a BufferedReader.
   * @param reader The reader positioned at the SEQUENCE TLV.
   */
  CASN1Sequence(BufferedReader& reader);

  /**
   * @brief Constructs a SEQUENCE from a generic ASN.1 object.
   * @param obj The ASN.1 object to reinterpret as a SEQUENCE.
   */
  CASN1Sequence(const CASN1Object& obj);

  /**
   * @brief Constructs a SEQUENCE from a raw byte buffer.
   * @param value Pointer to DER-encoded data.
   * @param len   Length of the data in bytes.
   */
  CASN1Sequence(const BYTE* value, long len);

 private:
  static const BYTE TAG;
};
