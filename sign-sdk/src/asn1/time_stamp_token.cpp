// SPDX-License-Identifier: LGPL-3.0-or-later
// TimeStampToken.cpp: implementation of the CTimeStampToken class.
#include "asn1/time_stamp_token.h"

#include "asn1/content_info.h"
#include "asn1_octet_string.h"
#include "signed_data.h"

CTimeStampToken::CTimeStampToken(BufferedReader& reader)
    : CContentInfo(reader) {}

CTimeStampToken::CTimeStampToken(const CASN1Object& timeStampToken)
    : CContentInfo(timeStampToken) {}

CTimeStampToken::~CTimeStampToken() {}

CTSTInfo CTimeStampToken::getTSTInfo() {
  CSignedData signedData(getContent());

  CContentInfo contentInfo(signedData.getContentInfo());

  CASN1OctetString tst(contentInfo.getContent());

  BufferedReader reader(*tst.getValue());
  return CTSTInfo(reader);
}

int CTimeStampToken::verify(REVOCATION_INFO* pRevocationInfo) {
  CSignedData signedData(getContent());

  return signedData.verify(0, nullptr, pRevocationInfo);
}

int CTimeStampToken::verify(const char* szDateTime,
                            REVOCATION_INFO* pRevocationInfo) {
  CSignedData signedData(getContent());

  return signedData.verify(0, szDateTime, pRevocationInfo);
}

CASN1SetOf CTimeStampToken::getCertificates() {
  CSignedData signedData(getContent());

  return signedData.getCertificates();
}
