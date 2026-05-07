// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "signer_info_generator.h"

#include <ctime>

#include "asn1/algorithm_identifier.h"
#include "asn1/asn1_object_identifier.h"
#include "asn1/asn1_octet_string.h"
#include "asn1/asn1_sequence.h"
#include "asn1/asn1_set_of.h"
#include "asn1/asn1_utc_time.h"
#include "asn1/certificate.h"
#include "asn1/issuer_and_serial_number.h"
#include "asn1/signer_info.h"

CSignerInfoGenerator::CSignerInfoGenerator() {}

CSignerInfoGenerator::~CSignerInfoGenerator() = default;

void CSignerInfoGenerator::setContentHash(const BYTE *hash, int hashlen) {
  m_contentHash.append(ByteArray(ByteArray(ByteArray(hash, hashlen))));
}

void CSignerInfoGenerator::setSigningCertificate(const BYTE *certificate,
                                                 int certlen,
                                                 const BYTE *certHash,
                                                 int certHashLen) {
  m_signingCertificate.append(ByteArray(ByteArray(certificate, certlen)));
  m_certificateHash.append(ByteArray(ByteArray(certHash, certHashLen)));

  BufferedReader reader(m_signingCertificate);
  CCertificate cert(reader);

  CCertificateInfo certInfo = cert.getCertificateInfo();

  m_pIssuer = std::make_unique<CName>(certInfo.getIssuer());
  m_pSerialNumber = std::make_unique<CASN1Integer>(certInfo.getSerialNumber());
}

void CSignerInfoGenerator::setSignature(const BYTE *signature, int siglen) {
  m_signature.append(ByteArray(ByteArray(signature, siglen)));
}

void CSignerInfoGenerator::setTimestampToken(const BYTE *timestampToken,
                                             int tstlen) {
  m_timeStampToken.append(ByteArray(ByteArray(timestampToken, tstlen)));
}

void CSignerInfoGenerator::setTimestampToken(
    const CTimeStampToken *pTimestampToken) {
  pTimestampToken->toByteArray(m_timeStampToken);
}

void CSignerInfoGenerator::getSignedAttributes(ByteDynArray &signedAttribute,
                                               bool counterSignature,
                                               bool signingTime) {
  CASN1SetOf authAttributes;

  if (!counterSignature) {
    CASN1SetOf attrValues;
    CASN1Sequence attr;

    // content type
    CASN1ObjectIdentifier contentTypeOID(szContentTypeOID);
    attr.addElement(contentTypeOID);
    attrValues.addElement(CASN1ObjectIdentifier(szDataOID));
    attr.addElement(attrValues);
    authAttributes.addElement(attr);
  }

  if (signingTime) {
    // Signing Time
    CASN1SetOf attrValues2;
    CASN1Sequence attr2;

    attr2.removeAll();
    char szTime[20];
    time_t now = time(nullptr);
    strftime(szTime, 20, "%y%m%d%H%M%SZ", gmtime(&now));

    attr2.addElement(CASN1ObjectIdentifier(szSigningTimeOID));
    attrValues2.addElement(CASN1UTCTime(szTime));
    attr2.addElement(attrValues2);
    authAttributes.addElement(attr2);
  }

  // message digest
  CASN1SetOf attrValues1;
  CASN1Sequence attr1;

  attr1.addElement(CASN1ObjectIdentifier(szMessageDigestOID));
  attrValues1.addElement(CASN1OctetString(m_contentHash));
  attr1.addElement(attrValues1);
  authAttributes.addElement(attr1);

  // CaDES-BES

  // ESS-signing-certificate-v2
  CASN1SetOf attrValues3;
  CASN1Sequence attr3;

  attr3.addElement(CASN1ObjectIdentifier(szIdAASigningCertificateV2OID));

  CASN1Sequence certidv2s;

  certidv2s.addElement(CAlgorithmIdentifier(szSHA256OID));
  certidv2s.addElement(CASN1OctetString(m_certificateHash));

  certidv2s.addElement(
      CIssuerAndSerialNumber(*m_pIssuer, *m_pSerialNumber, false));

  CASN1Sequence signingCertificateV2;

  signingCertificateV2.addElement(certidv2s);

  CASN1Sequence innerSequence;
  innerSequence.addElement(signingCertificateV2);
  attrValues3.addElement(innerSequence);
  attr3.addElement(attrValues3);
  authAttributes.addElement(attr3);

  m_signedAttributes.clear();

  authAttributes.toByteArray(m_signedAttributes);
  authAttributes.toByteArray(signedAttribute);
}

void CSignerInfoGenerator::toByteArray(ByteDynArray &signerInfoArray) {
  // Create the SignerInfo
  CSignerInfo signerInfo = getSignerInfo();

  signerInfo.toByteArray(signerInfoArray);
}

CSignerInfo CSignerInfoGenerator::getSignerInfo() {
  // Create the SignerInfo
  CSignerInfo signerInfo(
      CIssuerAndSerialNumber(*m_pIssuer, *m_pSerialNumber, false),
      CAlgorithmIdentifier(szSHA256OID),
      CAlgorithmIdentifier(szSha256WithRsaEncryptionOID),
      CASN1OctetString(m_signature));

  if (m_signedAttributes.size() > 0)
    signerInfo.addAuthenticatedAttributes(CASN1SetOf(m_signedAttributes));

  buildUnsignedAttributes();

  if (m_unsignedAttributes.size() != 0)
    signerInfo.addUnauthenticatedAttributes(m_unsignedAttributes);

  return signerInfo;
}

void CSignerInfoGenerator::buildUnsignedAttributes() {
  m_unsignedAttributes.removeAll();

  if (m_timeStampToken.size() > 0) {
    CASN1Sequence v;
    v.addElement(CASN1ObjectIdentifier(szTimestampTokenOID));
    CASN1SetOf tst;
    tst.addElement(m_timeStampToken);
    v.addElement(tst);

    m_unsignedAttributes.addElement(v);
  }
}
