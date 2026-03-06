// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

/**
 * @file asn1_optional_field.h
 * @brief ASN.1 context-tagged optional field wrapper.
 *
 * Wraps an ASN.1 element with a context-specific (IMPLICIT or EXPLICIT)
 * tag, representing optional or CHOICE fields in CMS structures such
 * as the certificates [0] and crls [1] fields in SignedData.
 */

#pragma once

#include "asn1_object.h"

/**
 * @brief Context-tagged optional ASN.1 field.
 *
 * Re-tags an existing ASN.1 object with a context-specific class tag,
 * enabling IMPLICIT or EXPLICIT tagging of optional fields as defined
 * by the CMS/PKCS#7 ASN.1 module.
 */
class CASN1OptionalField : public CASN1Object {
 public:
  /**
   * @brief Constructs an optional field by reading from a BufferedReader.
   * @param reader The reader positioned at the tagged TLV.
   */
  CASN1OptionalField(BufferedReader& reader);

  /**
   * @brief Constructs an optional field by applying a context class tag.
   * @param pAsn1Obj The ASN.1 object to wrap.
   * @param btClass  The context-specific tag number.
   */
  CASN1OptionalField(const CASN1Object& pAsn1Obj, const BYTE& btClass);

  /**
   * @brief Constructs an optional field from an existing ASN.1 object.
   * @param opt The ASN.1 object to copy as an optional field.
   */
  CASN1OptionalField(const CASN1Object& opt);

  ~CASN1OptionalField();

  /**
   * @brief Returns the context-specific tag byte for this optional field.
   * @return The tag byte including class and tag number bits.
   */
  BYTE getTag() const;

 private:
  static const BYTE TAG;
  BYTE m_btClass;  ///< Context-specific tag number.
};
