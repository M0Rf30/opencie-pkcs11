// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

/**
 * @file pki_status_info.h
 * @brief PKIStatusInfo ASN.1 structure from RFC 3161 timestamp protocol.
 *
 * Represents the PKIStatusInfo field returned in a TimeStampResponse,
 * indicating whether the TSA granted or rejected the timestamp request
 * and providing a status code for programmatic evaluation.
 */

#pragma once

#include "asn1/asn1_integer.h"
#include "asn1/asn1_object.h"
#include "asn1/asn1_sequence.h"
#include "asn1/buffered_reader.h"

/**
 * @brief PKIStatusInfo from RFC 3161 Section 2.4.2.
 *
 * Contains a PKIStatus INTEGER whose value indicates the result of a
 * timestamp request: 0 = granted, 1 = grantedWithMods, 2 = rejection,
 * 3 = waiting, 4 = revocationWarning, 5 = revocationNotification.
 * May optionally contain PKIFreeText and PKIFailureInfo fields.
 */
class CPKIStatusInfo : public CASN1Sequence {
 public:
  /**
   * @brief Parses a PKIStatusInfo from a DER-encoded stream.
   * @param reader Buffered reader positioned at the PKIStatusInfo SEQUENCE.
   */
  CPKIStatusInfo(BufferedReader& reader);

  /**
   * @brief Constructs a PKIStatusInfo from an already-parsed ASN.1 object.
   * @param PKIStatusInfo Generic ASN.1 object containing PKIStatusInfo
   * encoding.
   */
  CPKIStatusInfo(const CASN1Object& PKIStatusInfo);

  virtual ~CPKIStatusInfo();

  /** @brief Returns the PKIStatus integer value. */
  CASN1Integer getStatus();
};
