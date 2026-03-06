// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

#include "time_stamp_request.h"

#include "asn1/asn1_octet_string.h"
#include "asn1_boolean.h"

CTimeStampRequest::CTimeStampRequest(BufferedReader& reader)
    : CASN1Sequence(reader) {}

CTimeStampRequest::CTimeStampRequest(const CASN1Object& timeStampToken)
    : CASN1Sequence(timeStampToken) {}

CTimeStampRequest::CTimeStampRequest(const char* szHashAlgoOID,
                                     ByteDynArray& digest,
                                     const char* szPolicyOID,
                                     CASN1Integer& nounce)
    : CASN1Sequence() {
  addElement(CASN1Integer(1));
  CASN1Sequence messageImprint;

  messageImprint.addElement(CAlgorithmIdentifier(szHashAlgoOID));
  messageImprint.addElement(CASN1OctetString(digest));
  addElement(messageImprint);

  if (szPolicyOID != nullptr && strlen(szPolicyOID) > 0) {
    CASN1ObjectIdentifier policyOid(szPolicyOID);  //"1.3.6.1.4.1.29741.1.1.6");
    addElement(policyOid);
  }

  addElement(nounce);
  addElement(CASN1Boolean(true));  // certReq
}

CTimeStampRequest::~CTimeStampRequest() {}
