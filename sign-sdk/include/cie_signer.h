// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file cie_signer.h
 * @brief CIE smart card signer implementing the CBaseSigner interface.
 */

#pragma once

#include <memory>

#include "asn1/certificate.h"
#include "asn1/rsa_private_key.h"
#include "base_signer.h"
#include "csp/ias.h"

/**
 * Concrete signer that uses the CIE card's IAS-ECC interface for digital
 * signatures.
 */
class CCIESigner : public CBaseSigner {
 public:
  CCIESigner(IAS* pIAS);
  virtual ~CCIESigner(void);

  /**
   * Initialize the signer by verifying the user PIN on the CIE card.
   *
   * @param szPIN  Null-terminated PIN string to verify.
   * @return 0 on success, non-zero error code on failure.
   */
  long Init(const char* szPIN);

  /** @copydoc CBaseSigner::GetCertificate */
  virtual long GetCertificate(const char* alias, CCertificate** ppCertificate,
                              ByteDynArray& id);

  /** @copydoc CBaseSigner::Sign */
  virtual long Sign(ByteDynArray& data, ByteDynArray& id, int algo,
                    ByteDynArray& signature);

  /** @copydoc CBaseSigner::Close */
  virtual long Close();

 private:
  IAS* m_pIAS;     /**< IAS interface for card communication. */
  char m_szPIN[9]; /**< Cached user PIN (8 digits + null terminator). */
  std::unique_ptr<CCertificate> m_pCertificate;
};
