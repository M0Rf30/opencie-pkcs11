// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file counter_signature_generator.h
 * @brief CMS counter-signature generator for adding signatures to existing
 *        SignedData.
 */

#pragma once

#include "signed_document.h"
#include "signer_info_generator.h"
#include "util/array.h"

/**
 * Generates a counter-signature over an existing signer's signature value,
 * as defined in CMS (RFC 5652). Used for adding notarization or second-party
 * acknowledgment.
 */
class CounterSignatureGenerator {
 public:
  CounterSignatureGenerator(CSignedDocument& signedDoc, int signerInfoIndex);

  virtual ~CounterSignatureGenerator();

  /** Extract the original content from the parent signed document. */
  void getContent(ByteDynArray& content);

  /** Set a pre-computed content hash instead of computing from content. */
  void setContentHash(const BYTE* hash, int hashlen);

  /** Set the signer's certificate and its hash for the ESSCertIDv2 attribute.
   */
  void setSigningCertificate(const BYTE* certificate, int certlen,
                             const BYTE* certHash, int certHashLen);

  /** Set the raw RSA signature value. */
  void setSignature(const BYTE* signature, int siglen);

  /** Attach a timestamp token as an unsigned attribute. */
  void setTimestampToken(const BYTE* timestampToken, int tstlen);

  /** Serialize the authenticated attributes for signing. */
  void getSignedAttributes(ByteDynArray& signedAttribute);

  /** Serialize the complete signed document with the counter-signature added.
   */
  void toByteArray(ByteDynArray& signedDoc);

 private:
  CSignedDocument m_signedDoc;
  CSignerInfo m_signerInfo;
  int m_signerInfoIndex;

  ByteDynArray m_signingCertificate;
  CASN1SetOf m_signerInfos;
  CASN1SetOf m_certificates;
  CASN1SetOf m_digestAlgos;

  CSignerInfoGenerator m_signerInfoGenerator;
};
