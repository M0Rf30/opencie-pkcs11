// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file relative_distinguished_name.h
 * @brief X.500 RelativeDistinguishedName ASN.1 structure.
 *
 * Represents a single RDN (RFC 5280 Section 4.1.2.4) — a SET OF
 * attribute type/value pairs that forms one component of an X.500
 * distinguished name.
 */

#pragma once

#include "asn1_set_of.h"

/**
 * @brief RelativeDistinguishedName (RFC 5280 Section 4.1.2.4).
 *
 * An RDN is a SET OF AttributeTypeAndValue pairs. Typically each RDN
 * contains a single attribute (e.g. CN=..., O=..., C=...). Multiple
 * RDNs form a complete X.500 Name used for issuer/subject identification.
 */
class CRelativeDistinguishedName : public CASN1SetOf {
 public:
  /**
   * @brief Parses an RDN from a DER-encoded stream.
   * @param reader Buffered reader positioned at the SET.
   */
  CRelativeDistinguishedName(BufferedReader& reader);

  /** @brief Constructs an empty RDN. */
  CRelativeDistinguishedName();

  /**
   * @brief Constructs an RDN from an already-parsed ASN.1 object.
   * @param rname Generic ASN.1 object containing RDN encoding.
   */
  CRelativeDistinguishedName(const CASN1Object& rname);

  virtual ~CRelativeDistinguishedName();
};
