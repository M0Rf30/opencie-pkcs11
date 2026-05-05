// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file time_stamp_request.h
 * @brief RFC 3161 TimeStampReq ASN.1 structure.
 *
 * Represents a timestamp request sent to a Time Stamping Authority (TSA),
 * containing the hash algorithm, message imprint digest, optional policy
 * OID, and a nonce for replay protection.
 */

#pragma once

#include "asn1/time_stamp_token.h"

/**
 * @brief RFC 3161 TimeStampReq (Section 2.4.1).
 *
 * Encodes a timestamp request containing the version, MessageImprint
 * (hash algorithm + digest), optional TSAPolicyId, and an optional
 * nonce INTEGER for replay detection.
 */
class CTimeStampRequest : public CASN1Sequence {
 public:
  /**
   * @brief Parses a TimeStampReq from a DER-encoded stream.
   * @param reader Buffered reader positioned at the TimeStampReq SEQUENCE.
   */
  explicit CTimeStampRequest(BufferedReader& reader);

  /**
   * @brief Constructs a TimeStampReq from an already-parsed ASN.1 object.
   * @param timeStampToken Generic ASN.1 object containing the request encoding.
   */
  explicit CTimeStampRequest(const CASN1Object& timeStampToken);

  /**
   * @brief Constructs a TimeStampReq from explicit components.
   * @param szHashAlgoOID Dotted-decimal OID of the hash algorithm (e.g.
   * SHA-256).
   * @param digest        The message imprint (hash of the data to timestamp).
   * @param szPolicyOID   Optional TSA policy OID (may be nullptr).
   * @param nounce        Nonce integer for replay protection.
   */
  CTimeStampRequest(const char* szHashAlgoOID, ByteDynArray& digest,
                    const char* szPolicyOID, CASN1Integer& nounce);

  virtual ~CTimeStampRequest();
};
