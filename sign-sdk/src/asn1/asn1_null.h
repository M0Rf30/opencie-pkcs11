// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

/**
 * @file asn1_null.h
 * @brief ASN.1 NULL type (tag 0x05).
 *
 * Represents the ASN.1 NULL value, typically used as a placeholder
 * for absent algorithm parameters in AlgorithmIdentifier structures.
 */

#pragma once

#include "asn1_object.h"

/**
 * @brief ASN.1 NULL (tag 0x05).
 *
 * A zero-length value used where the ASN.1 schema requires a present
 * but empty parameter, such as the parameters field of an
 * AlgorithmIdentifier for RSA (sha256WithRSAEncryption).
 */
class CASN1Null : public CASN1Object {
 private:
  static const BYTE TAG;

 public:
  /**
   * @brief Constructs a NULL by reading from a BufferedReader.
   * @param reader The reader positioned at the NULL TLV.
   */
  CASN1Null(BufferedReader& reader);

  /** @brief Constructs a default ASN.1 NULL value. */
  CASN1Null();

  ~CASN1Null();
};
