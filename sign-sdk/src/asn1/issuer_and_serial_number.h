// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

/**
 * @file issuer_and_serial_number.h
 * @brief CMS IssuerAndSerialNumber ASN.1 structure.
 *
 * Represents the IssuerAndSerialNumber type (RFC 5652 Section 10.2.4)
 * used within SignerInfo to uniquely identify a signer's certificate
 * by its issuer distinguished name and serial number.
 */

#pragma once

#include "asn1/asn1_integer.h"
#include "asn1/asn1_sequence.h"
#include "name.h"

/**
 * @brief IssuerAndSerialNumber (RFC 5652 Section 10.2.4).
 *
 * A SEQUENCE containing an issuer Name and a certificate serial number
 * INTEGER, used to match a SignerInfo to the corresponding X.509
 * certificate within a SignedData's certificate set.
 */
class CIssuerAndSerialNumber : public CASN1Sequence {
 public:
  /**
   * @brief Parses an IssuerAndSerialNumber from a DER-encoded stream.
   * @param reader Buffered reader positioned at the SEQUENCE.
   */
  CIssuerAndSerialNumber(BufferedReader& reader);

  /**
   * @brief Constructs from an already-parsed ASN.1 object.
   * @param issuerAndSerNum Generic ASN.1 object with the encoding.
   */
  CIssuerAndSerialNumber(const CASN1Object& issuerAndSerNum);

  /**
   * @brief Constructs from explicit issuer name and serial number.
   * @param issuer          The issuer distinguished name.
   * @param serNum          The certificate serial number.
   * @param contextSpecific If true, wraps elements with context-specific tags.
   */
  CIssuerAndSerialNumber(const CName& issuer, const CASN1Integer& serNum,
                         bool contextSpecific);

  virtual ~CIssuerAndSerialNumber();
};
