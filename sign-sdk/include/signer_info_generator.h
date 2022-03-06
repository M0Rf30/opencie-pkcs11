// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include "asn1/issuer_and_serial_number.h"
#include "asn1/signer_info.h"
#include "Util/definitions.h"
#include "Util/byte_array.h"
#include <memory>

class CSignerInfoGenerator {
 public:
  CSignerInfoGenerator();

  virtual ~CSignerInfoGenerator();

  void setContent(const BYTE* content, int len);

  void setContentHash(const BYTE* hash, int hashlen);

  void setSigningCertificate(const BYTE* certificate, int certlen,
                             const BYTE* certHash, int certHashLen);

  void setSignature(const BYTE* signature, int siglen);

  void setTimestampToken(const BYTE* timestampToken, int tstlen);

  void setTimestampToken(const CTimeStampToken* pTimestampToken);

  void getSignedAttributes(UUCByteArray& signedAttribute, bool countersignature,
                           bool signingTime);

  void toByteArray(UUCByteArray& signerInfo);

  CSignerInfo getSignerInfo();

 private:
  UUCByteArray m_content;
  UUCByteArray m_contentHash;
  UUCByteArray m_signingCertificate;
  UUCByteArray m_signature;
  UUCByteArray m_signedAttributes;
  CASN1SetOf m_unsignedAttributes;
  UUCByteArray m_certificateHash;
  UUCByteArray m_timeStampToken;
  CASN1SetOf m_counterSignatures;
  void buildUnsignedAttributes();
  std::unique_ptr<CName> m_pIssuer;
  std::unique_ptr<CASN1Integer> m_pSerialNumber;
};
