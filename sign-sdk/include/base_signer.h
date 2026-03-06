// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file base_signer.h
 * @brief Abstract interface for cryptographic signers.
 */

#pragma once

#include "asn1/certificate.h"

/**
 * Abstract base class for cryptographic signing providers.
 *
 * Subclasses implement certificate retrieval and signing using specific
 * card types or PKCS#11 tokens.
 */
class CBaseSigner {
 public:
  virtual ~CBaseSigner() {};

  /**
   * Retrieve the signer's certificate and a key identifier.
   *
   * @param alias          Certificate alias to look up.
   * @param ppCertificate  Output pointer receiving the certificate object.
   * @param id             Output buffer receiving the key identifier.
   * @return 0 on success, non-zero error code on failure.
   */
  virtual long GetCertificate(const char* alias, CCertificate** ppCertificate,
                              ByteDynArray& id) = 0;

  /**
   * Sign data using the specified algorithm.
   *
   * @param data       Data to be signed.
   * @param id         Key identifier selecting the signing key.
   * @param algo       Algorithm identifier (ALGO_SHA1 or ALGO_SHA256).
   * @param signature  Output buffer receiving the resulting signature.
   * @return 0 on success, non-zero error code on failure.
   */
  virtual long Sign(ByteDynArray& data, ByteDynArray& id, int algo,
                    ByteDynArray& signature) = 0;

  /** Release signer resources. */
  virtual long Close() = 0;
};
