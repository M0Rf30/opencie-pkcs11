// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

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

  /**
   * Load the embedded set of public Italian CIE root/sub-CA certificates
   * (see sign-sdk/src/cie_ca_certs_data.h) into the store, so that OCSP
   * response and CRL signature verification can find the issuing CA even
   * when the CMS being verified carries only the signer certificate (the
   * common case for CIE-signed PDFs). Idempotent and safe to call before
   * every verification -- repeated calls are cheap map re-insertions.
   */
  static void LoadBuiltInCieCertificates();

  /** Free all stored certificates. */
  static void CleanUp();

 private:
  static std::map<unsigned long, CCertificate*> m_certMap;
};
