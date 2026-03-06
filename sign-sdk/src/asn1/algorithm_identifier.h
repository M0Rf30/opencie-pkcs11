// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

/**
 * @file algorithm_identifier.h
 * @brief ASN.1 AlgorithmIdentifier structure (OID + optional parameters).
 *
 * Implements the AlgorithmIdentifier type defined in RFC 5652 and
 * X.509, used throughout CMS/PKCS#7 to identify digest algorithms,
 * signature algorithms, and key encryption algorithms.
 */

#pragma once

#include "asn1/asn1_sequence.h"
#include "asn1_object_identifier.h"

/**
 * @brief ASN.1 AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY
 * OPTIONAL }.
 *
 * Represents the standard AlgorithmIdentifier used in CMS SignedData
 * (digestAlgorithms, signatureAlgorithm) and X.509 certificates
 * (signature, subjectPublicKeyInfo).
 */
class CAlgorithmIdentifier : public CASN1Sequence {
 public:
  /**
   * @brief Constructs an AlgorithmIdentifier from a generic ASN.1 object.
   * @param algoId The ASN.1 object to reinterpret as an AlgorithmIdentifier.
   */
  CAlgorithmIdentifier(const CASN1Object& algoId);

  /**
   * @brief Constructs an AlgorithmIdentifier by reading from a BufferedReader.
   * @param reader The reader positioned at the AlgorithmIdentifier SEQUENCE
   * TLV.
   */
  CAlgorithmIdentifier(BufferedReader& reader);

  /**
   * @brief Constructs an AlgorithmIdentifier from a dotted OID string.
   * @param szObjId Null-terminated OID string (e.g., "1.2.840.113549.1.1.11").
   */
  CAlgorithmIdentifier(const char* szObjId);

  /**
   * @brief Constructs an AlgorithmIdentifier from an OBJECT IDENTIFIER.
   * @param objId The algorithm OID.
   */
  CAlgorithmIdentifier(const CASN1ObjectIdentifier& objId);

  /**
   * @brief Returns the algorithm OID.
   * @return The OBJECT IDENTIFIER for this algorithm.
   */
  CASN1ObjectIdentifier getOID();

  /**
   * @brief Returns the algorithm parameters, if present.
   * @return The parameters field (often ASN.1 NULL for RSA-based algorithms).
   */
  CASN1Object getParameters();
};
