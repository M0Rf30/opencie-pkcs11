// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "signed_data_generator_ex.h"

#include <memory>

#include "asn1/asn1_object_identifier.h"
#include "asn1/asn1_octet_string.h"
#include "asn1/asn1_set_of.h"
#include "util/definitions.h"

SignedDataGeneratorEx::SignedDataGeneratorEx(CSignedDocument& sd)
    : m_signerInfos(sd.getSignerInfos()),
      m_certificates(sd.getCertificates()),
      m_digestAlgos(sd.getDigestAlgos()) {
  if (!sd.isDetached()) sd.getContent(m_content);
}

SignedDataGeneratorEx::~SignedDataGeneratorEx() {}

bool SignedDataGeneratorEx::isDetached() { return m_content.size() == 0; }

void SignedDataGeneratorEx::setContent(const BYTE* content, int len) {
  m_content.append(ByteArray(content, len));
}

void SignedDataGeneratorEx::addSigners(CSignedDocument& sd) {
  CASN1SetOf signerInfos = sd.getSignerInfos();
  int size = signerInfos.size();
  for (int i = 0; i < size; i++) {
    m_signerInfos.addElement(signerInfos.elementAt(i));
  }

  CASN1SetOf certificates = sd.getCertificates();
  size = certificates.size();
  for (int i = 0; i < size; i++) {
    m_certificates.addElement(certificates.elementAt(i));
  }
}

void SignedDataGeneratorEx::addCounterSignature(
    CSignerInfo& signerInfoRef, CSignedDocument& counterSignature) {
  // il signeddocument contiene solo un signerinfo ritornato dal webservice
  CSignerInfo signerInfoToAdd(counterSignature.getSignerInfos().elementAt(0));

  int size = m_signerInfos.size();

  for (int i = 0; i < size; i++) {
    CSignerInfo si(m_signerInfos.elementAt(i));
    bool res = addCounterSignature(si, signerInfoRef, signerInfoToAdd);
    if (res) {
      m_signerInfos.setElementAt(si, i);

      CASN1SetOf certificates = counterSignature.getCertificates();
      int certSize = certificates.size();
      for (int j = 0; j < certSize; j++) {
        m_certificates.addElement(certificates.elementAt(j));
      }

      return;
    }
  }
}

void SignedDataGeneratorEx::addCounterSignature(
    CSignerInfo& signerInfoRef, CSignedDocument& counterSignature,
    CTimeStampResponse& tsr) {
  // il signeddocument contiene solo un signerinfo ritornato dal webservice
  CSignerInfo signerInfoToAdd(counterSignature.getSignerInfos().elementAt(0));

  CTimeStampToken tst(tsr.getTimeStampToken());
  signerInfoToAdd.setTimeStampToken(tst);

  int size = m_signerInfos.size();

  for (int i = 0; i < size; i++) {
    CSignerInfo si(m_signerInfos.elementAt(i));
    bool res = addCounterSignature(si, signerInfoRef, signerInfoToAdd);
    if (res) {
      m_signerInfos.setElementAt(si, i);

      CASN1SetOf certificates = counterSignature.getCertificates();
      int certSize = certificates.size();
      for (int j = 0; j < certSize; j++) {
        m_certificates.addElement(certificates.elementAt(j));
      }

      return;
    }
  }
}

bool SignedDataGeneratorEx::addCounterSignature(CSignerInfo& signerInfo,
                                                CSignerInfo& signerInfoRef,
                                                CSignerInfo& counterSignature) {
  if (signerInfo == signerInfoRef) {
    signerInfo.addCountersignatures(counterSignature);
    return true;
  }

  CASN1SetOf countersignatures(signerInfo.getCountersignatures());

  int size = countersignatures.size();

  for (int i = 0; i < size; i++) {
    CSignerInfo si(countersignatures.elementAt(i));
    if (addCounterSignature(si, signerInfoRef, counterSignature)) {
      signerInfo.setCountersignatures(i, si);
      return true;
    }
  }

  return false;
}

void SignedDataGeneratorEx::setTimestamp(CTimeStampResponse& tsr,
                                         int signerInfoIndex) {
  CSignerInfo si(m_signerInfos.elementAt(signerInfoIndex));
  CTimeStampToken tst = tsr.getTimeStampToken();
  si.setTimeStampToken(tst);
  m_signerInfos.setElementAt(si, signerInfoIndex);
}

void SignedDataGeneratorEx::toByteArray(ByteDynArray& pkcs7SignedData) {
  const char* dataOID = szDataOID;
  // Create signedData
  std::unique_ptr<CSignedData> pSignedData;
  if (m_content.size() == 0) {
    CContentType contentType(dataOID);
    pSignedData =
        std::make_unique<CSignedData>(m_digestAlgos, CContentInfo(contentType),
                                      m_signerInfos, m_certificates);
  } else {
    // Create signedData
    pSignedData = std::make_unique<CSignedData>(
        m_digestAlgos,
        CContentInfo(CContentType(szDataOID), CASN1OctetString(m_content)),
        m_signerInfos, m_certificates);
  }

  // Finally create ContentInfo
  CContentInfo contentInfo(CContentType(szSignedDataOID), *pSignedData);

  contentInfo.toByteArray(pkcs7SignedData);
}
