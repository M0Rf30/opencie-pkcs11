// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "time_stamp_response.h"

#include "asn1/time_stamp_token.h"

CTimeStampResponse::CTimeStampResponse(BufferedReader& reader)
    : CASN1Sequence(reader) {}

CTimeStampResponse::CTimeStampResponse(const CASN1Object& timeStampresponse)
    : CASN1Sequence(timeStampresponse) {}

CTimeStampResponse::CTimeStampResponse(const BYTE* content, int length)
    : CASN1Sequence(content, length) {}

CTimeStampResponse::~CTimeStampResponse() {}

CTimeStampToken CTimeStampResponse::getTimeStampToken() {
  return CTimeStampToken(elementAt(1));
}

CPKIStatusInfo CTimeStampResponse::getPKIStatusInfo() {
  return CPKIStatusInfo(elementAt(0));
}

int CTimeStampResponse::verify() { return verify(nullptr); }

int CTimeStampResponse::verify(const char* szDateTime) {
  CTimeStampToken tst(elementAt(1));
  return tst.verify(szDateTime, nullptr);
}
