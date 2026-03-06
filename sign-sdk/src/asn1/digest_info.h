// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file digest_info.h
 * @brief PKCS#1 DigestInfo ASN.1 structure.
 *
 * Represents the DigestInfo SEQUENCE used in PKCS#1 v1.5 RSA signatures
 * and various CMS operations, pairing a digest algorithm identifier
 * with the actual message digest value.
 *
 * @code
 * DigestInfo ::= SEQUENCE {
 *     digestAlgorithm DigestAlgorithmIdentifier,
 *     digest          Digest
 * }
 * @endcode
 */

#pragma once

#include "asn1/algorithm_identifier.h"
#include "asn1/asn1_sequence.h"
#include "asn1_octet_string.h"

/**
 * @brief PKCS#1 DigestInfo (RFC 8017 Section 9.2).
 *
 * Pairs a DigestAlgorithmIdentifier with the corresponding message
 * digest value. Used as the input to PKCS#1 v1.5 signature encoding
 * and for verifying signed message digests.
 */
class CDigestInfo : public CASN1Sequence {
 public:
  /**
   * @brief Parses a DigestInfo from a DER-encoded stream.
   * @param reader Buffered reader positioned at the DigestInfo SEQUENCE.
   */
  CDigestInfo(BufferedReader& reader);

  /**
   * @brief Constructs a DigestInfo from algorithm and digest components.
   * @param algoId The digest algorithm identifier.
   * @param digest The message digest value.
   */
  CDigestInfo(const CAlgorithmIdentifier& algoId,
              const CASN1OctetString& digest);

  /**
   * @brief Constructs from an already-parsed ASN.1 object.
   * @param digestInfo Generic ASN.1 object containing DigestInfo encoding.
   */
  CDigestInfo(const CASN1Object& digestInfo);

  /** @brief Returns the digest algorithm identifier. */
  CAlgorithmIdentifier getDigestAlgorithm();

  /** @brief Returns the message digest as an OCTET STRING. */
  CASN1OctetString getDigest();
};
