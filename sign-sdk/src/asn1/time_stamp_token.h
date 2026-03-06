// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

/**
 * @file time_stamp_token.h
 * @brief RFC 3161 TimeStampToken ASN.1 structure.
 *
 * A TimeStampToken is a CMS ContentInfo whose content is a TSTInfo,
 * providing cryptographic proof that data existed at a specific time.
 * Used in CAdES-T signatures and countersignature timestamps.
 */

#pragma once

#include "asn1/asn1_set_of.h"
#include "asn1/content_info.h"
#include "sign/cie_sign_api.h"
#include "tst_info.h"

/**
 * @brief RFC 3161 TimeStampToken.
 *
 * Extends CContentInfo to represent a timestamp token whose encapsulated
 * content is a signed TSTInfo. Provides verification of the timestamp
 * signature and access to the embedded certificates and TSTInfo fields.
 */
class CTimeStampToken : public CContentInfo {
 public:
  /**
   * @brief Parses a TimeStampToken from a DER-encoded stream.
   * @param reader Buffered reader positioned at the ContentInfo SEQUENCE.
   */
  CTimeStampToken(BufferedReader& reader);

  /**
   * @brief Constructs a TimeStampToken from an already-parsed ASN.1 object.
   * @param timeStampToken Generic ASN.1 object containing the token encoding.
   */
  CTimeStampToken(const CASN1Object& timeStampToken);

  /** @brief Extracts and returns the embedded TSTInfo structure. */
  CTSTInfo getTSTInfo();

  virtual ~CTimeStampToken();

  /**
   * @brief Verifies the timestamp token signature at current time.
   * @param pRevocationInfo Output revocation details for the TSA certificate.
   * @return 0 on success, non-zero error code on failure.
   */
  int verify(REVOCATION_INFO* pRevocationInfo);

  /**
   * @brief Verifies the timestamp token signature at a specific time.
   * @param szDateTime      Reference date/time string.
   * @param pRevocationInfo Output revocation details for the TSA certificate.
   * @return 0 on success, non-zero error code on failure.
   */
  int verify(const char* szDateTime, REVOCATION_INFO* pRevocationInfo);

  /** @brief Returns the SET OF certificates embedded in the timestamp token. */
  CASN1SetOf getCertificates();
};
