// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file asn1_set_of.h
 * @brief ASN.1 SET OF container (tag 0x31).
 *
 * Represents an unordered collection of ASN.1 elements of the same type,
 * used in CMS/PKCS#7 for digestAlgorithms, signerInfos, and certificates
 * fields in SignedData.
 */

#pragma once

#include "asn1_generic_sequence.h"
#include "asn1_object.h"

/** @brief Maximum number of objects in a SET OF container. */
#define MAX_OBJ 10

/**
 * @brief ASN.1 SET OF (tag 0x31) container.
 *
 * Specializes CASN1GenericSequence with the SET tag. Elements are
 * accessed positionally but semantically represent an unordered set,
 * with DER requiring a canonical ordering of the encoded elements.
 */
class CASN1SetOf : public CASN1GenericSequence {
 public:
  virtual ~CASN1SetOf() override;

  /** @brief Constructs an empty SET OF. */
  CASN1SetOf();

  /**
   * @brief Constructs a SET OF by reading from a BufferedReader.
   * @param reader The reader positioned at the SET OF TLV.
   */
  explicit CASN1SetOf(BufferedReader& reader);

  /**
   * @brief Constructs a SET OF from a generic ASN.1 object.
   * @param obj The ASN.1 object to reinterpret as a SET OF.
   */
  explicit CASN1SetOf(const CASN1Object&);

 private:
  static const BYTE TAG;
};
