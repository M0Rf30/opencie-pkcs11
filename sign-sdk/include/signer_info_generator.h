// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

/**
 * @file signer_info_generator.h
 * @brief CMS SignerInfo structure builder for digital signatures.
 */

#pragma once

#include <memory>

#include "asn1/issuer_and_serial_number.h"
#include "asn1/signer_info.h"
#include "util/array.h"
#include "util/definitions.h"

/**
 * Builds a CMS SignerInfo structure step by step: content, certificate,
 * signed attributes, signature value, and optional timestamp token.
 */
class CSignerInfoGenerator {
 public:
  CSignerInfoGenerator();

  virtual ~CSignerInfoGenerator();

  /** Set the content being signed (used to compute the message digest). */
  void setContent(const BYTE* content, int len);

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

  /** Attach a timestamp token as an unsigned attribute. */
  void setTimestampToken(const CTimeStampToken* pTimestampToken);

  /** Serialize the authenticated attributes for signing. */
  void getSignedAttributes(ByteDynArray& signedAttribute, bool countersignature,
                           bool signingTime);

  /** Serialize the complete SignerInfo to DER-encoded bytes. */
  void toByteArray(ByteDynArray& signerInfo);

  /** Return a parsed CSignerInfo object from the built data. */
  CSignerInfo getSignerInfo();

 private:
  ByteDynArray m_content;
  ByteDynArray m_contentHash;
  ByteDynArray m_signingCertificate;
  ByteDynArray m_signature;
  ByteDynArray m_signedAttributes;
  CASN1SetOf m_unsignedAttributes;
  ByteDynArray m_certificateHash;
  ByteDynArray m_timeStampToken;
  CASN1SetOf m_counterSignatures;
  void buildUnsignedAttributes();
  std::unique_ptr<CName> m_pIssuer;
  std::unique_ptr<CASN1Integer> m_pSerialNumber;
};
