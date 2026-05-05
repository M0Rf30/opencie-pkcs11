// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file tst_info.h
 * @brief RFC 3161 TSTInfo ASN.1 structure.
 *
 * Represents the TSTInfo SEQUENCE embedded within a TimeStampToken,
 * containing the timestamp's serial number, generation time, message
 * imprint, digest algorithm, and optional TSA name.
 */

#pragma once

#include "asn1/algorithm_identifier.h"
#include "asn1/asn1_integer.h"
#include "asn1/asn1_sequence.h"
#include "asn1/asn1_utc_time.h"
#include "name.h"

/**
 * @brief TSTInfo from RFC 3161 Section 2.4.2.
 *
 * Contains the core fields of a timestamp token: version, policy OID,
 * MessageImprint (hash algorithm + digest), serial number, generation
 * time, and the optional TSA name for identifying the issuing authority.
 */
class CTSTInfo : public CASN1Sequence {
 public:
  /**
   * @brief Parses a TSTInfo from a DER-encoded stream.
   * @param reader Buffered reader positioned at the TSTInfo SEQUENCE.
   */
  explicit CTSTInfo(BufferedReader& reader);

  /**
   * @brief Constructs from an already-parsed ASN.1 object.
   * @param tstInfo Generic ASN.1 object containing TSTInfo encoding.
   */
  explicit CTSTInfo(const CASN1Object& tstInfo);

  virtual ~CTSTInfo();

  /** @brief Returns the timestamp generation time. */
  CASN1UTCTime getUTCTime();

  /** @brief Returns the timestamp serial number. */
  CASN1Integer getSerialNumber();

  /** @brief Returns the digest algorithm from the MessageImprint. */
  CAlgorithmIdentifier getDigestAlgorithn();

  /** @brief Returns the MessageImprint SEQUENCE (algorithm + digest). */
  CASN1Sequence getMessageImprint();

  /**
   * @brief Returns the TSA name.
   * @note The TSAName field is optional; throws an exception if absent.
   */
  CName getTSAName();
};
