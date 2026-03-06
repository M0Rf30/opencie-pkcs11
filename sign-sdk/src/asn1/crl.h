// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

/**
 * @file crl.h
 * @brief X.509 Certificate Revocation List (CRL) ASN.1 structure.
 *
 * Represents a CRL (RFC 5280 Section 5) and provides a method to check
 * whether a certificate serial number appears on the revocation list.
 */

#pragma once

#include "asn1/asn1_integer.h"
#include "asn1/asn1_sequence.h"
#include "sign/cie_sign_api.h"

/**
 * @brief X.509 CRL (RFC 5280 Section 5).
 *
 * Wraps a DER-encoded CertificateList and supports revocation lookups
 * by serial number with an optional reference date for point-in-time
 * validation.
 */
class CCrl : public CASN1Sequence {
 public:
  /**
   * @brief Parses a CRL from a DER-encoded stream.
   * @param reader Buffered reader positioned at the CertificateList SEQUENCE.
   */
  CCrl(BufferedReader& reader);

  /**
   * @brief Constructs a CRL from an already-parsed ASN.1 object.
   * @param contentInfo Generic ASN.1 object containing CRL encoding.
   */
  CCrl(const CASN1Object& contentInfo);

  /**
   * @brief Checks whether a certificate is revoked in this CRL.
   * @param serialNumber    Serial number of the certificate to check.
   * @param szDateTime      Reference date/time for revocation comparison.
   * @param pReason         Output: CRL reason code (may be nullptr).
   * @param pRevocationInfo Output revocation details.
   * @return true if the certificate serial number is found on this CRL.
   */
  bool isRevoked(const CASN1Integer& serialNumber, const char* szDateTime,
                 int* pReason, REVOCATION_INFO* pRevocationInfo);
};
