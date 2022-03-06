// TimeStampToken.h: interface for the CTimeStampToken class.
//
#pragma once

#include "asn1/asn1_set_of.h"
#include "sign/disigonsdk.h"

#if _MSC_VER > 1000
#pragma once
#endif  // _MSC_VER > 1000

#include "asn1/content_info.h"
#include "tst_info.h"

class CTimeStampToken : public CContentInfo {
 public:
  CTimeStampToken(UUCBufferedReader& reader);

  CTimeStampToken(const CASN1Object& timeStampToken);

  CTSTInfo getTSTInfo();

  virtual ~CTimeStampToken();

  int verify(REVOCATION_INFO* pRevocationInfo);
  int verify(const char* szDateTime, REVOCATION_INFO* pRevocationInfo);

  CASN1SetOf getCertificates();
};

