// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file subject_public_key_info.h
 * @brief SubjectPublicKeyInfo ASN.1 structure from X.509 certificates.
 *
 * Represents the SubjectPublicKeyInfo SEQUENCE (RFC 5280 Section 4.1.2.7)
 * that carries the subject's public key algorithm identifier and the
 * public key bit string.
 */

#pragma once

#include "asn1/algorithm_identifier.h"
#include "asn1/asn1_sequence.h"
#include "asn1_bit_string.h"

/**
 * @brief SubjectPublicKeyInfo (RFC 5280 Section 4.1.2.7).
 *
 * Contains an AlgorithmIdentifier specifying the public key algorithm
 * (e.g. RSA, EC) and a BIT STRING holding the encoded public key value.
 */
class CSubjectPublicKeyInfo : public CASN1Sequence {
 public:
  /**
   * @brief Parses a SubjectPublicKeyInfo from a DER-encoded stream.
   * @param reader Buffered reader positioned at the SEQUENCE.
   */
  CSubjectPublicKeyInfo(BufferedReader& reader);

  /**
   * @brief Constructs from an already-parsed ASN.1 object.
   * @param obj Generic ASN.1 object containing the encoding.
   */
  CSubjectPublicKeyInfo(const CASN1Object& obj);

  virtual ~CSubjectPublicKeyInfo();

  /** @brief Returns the algorithm identifier for the public key. */
  CAlgorithmIdentifier getAlgorithmIdentifier();

  /** @brief Returns the public key as a BIT STRING. */
  CASN1BitString getPublicKey();
};
