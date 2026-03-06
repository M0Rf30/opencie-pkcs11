// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "signed_document.h"

#include <sys/types.h>

#include <algorithm>

#include "asn1/asn1_object.h"
#include "asn1/buffered_reader.h"
#include "asn1/certificate.h"
#include "crypto/base64.h"


CSignedDocument::CSignedDocument(const BYTE* content, int len) {
  LOG_DBG((0, "--> CSignedDocument", "CSignedDocument: %d", len));

  ByteDynArray c;

  if (content[0] == 'M' || content[0] == '-') {  // base64
    try {
      LOG_DBG((0, "CSignedDocument", "base64"));

      std::string encoded(reinterpret_cast<const char*>(content),
                          static_cast<size_t>(len));

      // strip PEM header/footer if present
      auto dash = encoded.find("--");
      if (dash != std::string::npos) {
        auto start = encoded.find('\n', dash);
        auto end = encoded.rfind("\n--");
        if (start != std::string::npos)
          encoded = encoded.substr(start + 1, end != std::string::npos
                                                  ? end - (start + 1)
                                                  : std::string::npos);
      }

      encoded.erase(
          std::remove_if(encoded.begin(), encoded.end(),
                         [](char c) { return c == '\r' || c == '\n'; }),
          encoded.end());

      ByteDynArray decoded;
      CBase64().Decode(encoded.c_str(), decoded);

      c.append(ByteArray(decoded.data(), decoded.size()));

    } catch (...) {
      throw 1;
    }
  } else {
    c.append(ByteArray(content, len));
  }

  if (!(c[0] == 0x30 && (c[1] & 0x80))) {
    throw -6;
  }

  BufferedReader r(c);

  m_pCMSSignedData = std::make_unique<CContentInfo>(r);
  if (!m_pCMSSignedData->getContentType().equals(
          CASN1ObjectIdentifier(szSignedDataOID))) {
    m_pCMSSignedData.reset();
    throw -1;
  }

  m_pSignedData = std::make_unique<CSignedData>(m_pCMSSignedData->getContent());
  m_signerInfos = m_pSignedData->getSignerInfos();
  m_certificates = m_pSignedData->getCertificates();
}

CSignedData CSignedDocument::getSignedData() { return *m_pSignedData; }

void CSignedDocument::toByteArray(ByteDynArray& signedData) {
  m_pCMSSignedData->toByteArray(signedData);
}

CSignedDocument::CSignedDocument(const CSignedDocument& CSignedDocument) {
  m_pCMSSignedData =
      std::make_unique<CContentInfo>(*CSignedDocument.m_pCMSSignedData);
  m_pSignedData = std::make_unique<CSignedData>(*m_pCMSSignedData->getValue());
  m_signerInfos = m_pSignedData->getSignerInfos();
  m_certificates = m_pSignedData->getCertificates();
}

CSignedDocument::~CSignedDocument() = default;

CASN1SetOf CSignedDocument::getSignerInfos() { return m_signerInfos; }

CASN1SetOf CSignedDocument::getCertificates() { return m_certificates; }

CASN1SetOf CSignedDocument::getDigestAlgos() {
  return m_pSignedData->getDigestAlgorithmIdentifiers();
}

void CSignedDocument::makeDetached() { m_pSignedData->makeDetached(); }

void CSignedDocument::setContent(ByteDynArray& content) {
  m_pSignedData->setContent(content);
}

int CSignedDocument::verify() { return verify(nullptr); }

int CSignedDocument::verify(const char* dateTime) {
  int bitmask = 0;
  // verifica la firma per ciascun signer
  for (size_t i = 0; i < m_signerInfos.size(); i++) {
    bitmask |= verify(static_cast<int>(i), dateTime, nullptr);
  }

  return bitmask;
}

int CSignedDocument::verify(int i, REVOCATION_INFO* pRevocationInfo) {
  return verify(i, nullptr, pRevocationInfo);
}

int CSignedDocument::verify(int i, const char* dateTime,
                            REVOCATION_INFO* pRevocationInfo) {
  // verify that the given certificate successfully handles and confirms
  // the signature associated with this signer and, if a signingTime
  // attribute is available, that the certificate was valid at the time the
  // signature was generated.

  return m_pSignedData->verify(i, dateTime, pRevocationInfo);
}

int CSignedDocument::getSignerCount() { return m_signerInfos.size(); }

CSignerInfo CSignedDocument::getSignerInfo(int index) {
  return m_signerInfos.elementAt(index);
}

void CSignedDocument::getContent(ByteDynArray& content) {
  CASN1OctetString octetString(reinterpret_cast<const char*>(
      m_pSignedData->getContentInfo().getValue()->data()));

  // content
  if (octetString.getTag() == 0x24) {  // contructed octet string
    CASN1Sequence contentArray(octetString);
    int size = contentArray.size();
    for (int i = 0; i < size; i++) {
      CASN1OctetString part(contentArray.elementAt(i));
      content.append(ByteArray(part.getValue()->data(), part.getLength()));
    }
  } else {
    content.append(
        ByteArray(octetString.getValue()->data(), octetString.getLength()));
  }
}

CCertificate CSignedDocument::getSignerCertificate(int index) {
  CSignerInfo sinfo = m_signerInfos.elementAt(index);

  CIssuerAndSerialNumber issuerAndSerialNumber =
      sinfo.getIssuerAndSerialNumber();

  for (size_t i = 0; i < m_certificates.size(); i++) {
    CCertificate cert = m_certificates.elementAt(i);
    CName issuer = cert.getIssuer();
    CASN1Integer serialNumber = cert.getSerialNumber();

    CIssuerAndSerialNumber issuerAndSerial(issuer, serialNumber, false);

    if (issuerAndSerial == issuerAndSerialNumber) {
      return cert;
    }
  }

  throw -1;
}

bool CSignedDocument::isDetached() {
  return m_pSignedData->getContentInfo().size() == 1;
}

// 0 successivo al 30 Giugno 2011, 1 successivo al 30 agosto 2010, 2 precedente
// al 30 agosto 2010
int CSignedDocument::get452009Range(char* szDateTime) {
  int flag452009 = 0;

  if (szDateTime) {
    try {
      CASN1UTCTime trentaGiugno2011("110630000000Z");

      CASN1UTCTime dateTime(szDateTime);

      // verifica 30 giugno 2011
      int len = dateTime.getLength() > trentaGiugno2011.getLength()
                    ? trentaGiugno2011.getLength()
                    : dateTime.getLength();

      if (memcmp(dateTime.getValue()->data(),
                 trentaGiugno2011.getValue()->data(), len) > 0) {
        flag452009 = 0;
      } else {
        CASN1UTCTime trentaAgosto2010("100830000000Z");
        len = dateTime.getLength() > trentaAgosto2010.getLength()
                  ? trentaAgosto2010.getLength()
                  : dateTime.getLength();

        if (memcmp(dateTime.getValue()->data(),
                   trentaAgosto2010.getValue()->data(), len) > 0) {
          flag452009 = 1;
        } else {
          flag452009 = 2;
        }
      }
    } catch (...) {
      // NSLog(@"DateTime parsing exception %s", szDateTime);
    }
  }

  return flag452009;
}
