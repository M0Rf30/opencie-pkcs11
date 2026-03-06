// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

/**
 * @file cert_store.h
 * @brief In-memory certificate store for CA certificate lookup.
 */

#pragma once

#include <map>

#include "asn1/certificate.h"

/**
 * Global in-memory store of trusted CA certificates, used during
 * certificate chain validation.
 */
class CCertStore {
 public:
  /** Add a CA certificate to the store. */
  static void AddCertificate(CCertificate& caCertificate);

  /**
   * Find the issuer CA certificate for the given certificate.
   *
   * @param certificate  Certificate whose issuer is to be looked up.
   * @return Pointer to the issuer certificate, or nullptr if not found.
   */
  static CCertificate* GetCertificate(CCertificate& certificate);

  /** Free all stored certificates. */
  static void CleanUp();

 private:
  static std::map<unsigned long, CCertificate*> m_certMap;
};
