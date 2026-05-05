// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file time_stamp_response.h
 * @brief RFC 3161 TimeStampResp ASN.1 structure.
 *
 * Represents the response returned by a Time Stamping Authority (TSA),
 * containing a PKIStatusInfo indicating success or failure and, on
 * success, the TimeStampToken with the cryptographic timestamp proof.
 */

#pragma once

#include "asn1/time_stamp_token.h"
#include "pki_status_info.h"

/**
 * @brief RFC 3161 TimeStampResp (Section 2.4.2).
 *
 * A SEQUENCE containing a PKIStatusInfo and an optional TimeStampToken.
 * The status must indicate "granted" or "grantedWithMods" for the
 * timestamp token to be present and valid.
 */
class CTimeStampResponse : public CASN1Sequence {
 public:
  /**
   * @brief Parses a TimeStampResp from a DER-encoded stream.
   * @param reader Buffered reader positioned at the SEQUENCE.
   */
  explicit CTimeStampResponse(BufferedReader& reader);

  /**
   * @brief Constructs from an already-parsed ASN.1 object.
   * @param timeStampresponse Generic ASN.1 object containing the encoding.
   */
  explicit CTimeStampResponse(const CASN1Object& timeStampresponse);

  /**
   * @brief Constructs from a raw DER byte buffer.
   * @param content Pointer to the DER-encoded response bytes.
   * @param length  Length of the buffer in bytes.
   */
  explicit CTimeStampResponse(const BYTE* content, int length);

  virtual ~CTimeStampResponse();

  /** @brief Extracts the TimeStampToken from the response. */
  CTimeStampToken getTimeStampToken();

  /** @brief Returns the PKIStatusInfo indicating request outcome. */
  CPKIStatusInfo getPKIStatusInfo();

  /**
   * @brief Verifies the timestamp response at a specific time.
   * @param szDateTime Reference date/time string.
   * @return 0 on success, non-zero error code on failure.
   */
  int verify(const char* szDateTime);

  /**
   * @brief Verifies the timestamp response at current time.
   * @return 0 on success, non-zero error code on failure.
   */
  int verify();
};
