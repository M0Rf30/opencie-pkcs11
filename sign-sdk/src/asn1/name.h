// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file name.h
 * @brief X.500 distinguished name ASN.1 structure and PKCS#9 OID constants.
 *
 * Represents an X.500 Name (RFC 5280 Section 4.1.2.4) — a sequence of
 * RelativeDistinguishedName sets used for issuer and subject fields in
 * X.509 certificates. Also defines OID constants for common PKCS#9
 * attributes and X.520 naming attributes.
 */

#pragma once

#include <string>

#include "asn1/asn1_sequence.h"

// PKCS#9 attribute OIDs (RFC 2985)
#define OID_EMAIL_ADDRESS "1.2.840.113549.1.9.1"
#define OID_UNSTRUCTURED_NAME "1.2.840.113549.1.9.2"
#define OID_CONTENT_TYPE "1.2.840.113549.1.9.3"
#define OID_MESSAGE_DIGEST "1.2.840.113549.1.9.4"
#define OID_SIGNING_TIME "1.2.840.113549.1.9.5"
#define OID_COUNTERSIGNATURE "1.2.840.113549.1.9.6"
#define OID_CHALLENGE_PASSWORD "1.2.840.113549.1.9.7"
#define OID_UNSTRUCTURED_ADDRESS "1.2.840.113549.1.9.8"

// X.520 naming attribute OIDs (RFC 4519)
#define OID_EXTENDED_CERTIFICATE_ATTRIBUTES "2.5.4.3"
#define OID_COMMON_NAME "2.5.4.3"
#define OID_SURNAME "2.5.4.4"
#define OID_COUNTRY_NAME "2.5.4.6"
#define OID_LOCALITY_NAME "2.5.4.7"
#define OID_STATE_OR_PROVINCE_NAME "2.5.4.8"
#define OID_ORGANIZATION_NAME "2.5.4.10"
#define OID_ORGANIZATIONAL_UNIT_NAME "2.5.4.11"
#define OID_TITLE "2.5.4.12"
#define OID_NAME "2.5.4.41"
#define OID_GIVEN_NAME "2.5.4.42"
#define OID_INITIALS "2.5.4.43"
#define OID_GENERATION_QUALIFIER "2.5.4.44"
#define OID_DN_QUALIFIER "2.5.4.46"
#define OID_SERIALNUMBER "2.5.4.5"

/**
 * @brief X.500 distinguished name (RFC 5280 Section 4.1.2.4).
 *
 * A Name is a SEQUENCE OF RelativeDistinguishedName sets, each
 * containing attribute type/value pairs (e.g. CN, O, C). Used as
 * the issuer and subject identifiers in X.509 certificates.
 */
class CName : public CASN1Sequence {
 public:
  /**
   * @brief Parses a Name from a DER-encoded stream.
   * @param reader Buffered reader positioned at the Name SEQUENCE.
   */
  CName(BufferedReader& reader);

  /**
   * @brief Constructs a Name from an already-parsed ASN.1 object.
   * @param name Generic ASN.1 object containing Name encoding.
   */
  CName(const CASN1Object& name);

  /**
   * @brief Retrieves a specific naming attribute by OID.
   * @param fieldOID Dotted-decimal OID string (e.g. OID_COMMON_NAME).
   * @return The attribute value as a string, or empty if not found.
   */
  std::string getField(const char* fieldOID);

  /**
   * @brief Serializes the full distinguished name into a human-readable string.
   * @param objId Output buffer receiving the DN string representation.
   */
  void getNameAsString(ByteDynArray& objId);

  virtual ~CName();
};
