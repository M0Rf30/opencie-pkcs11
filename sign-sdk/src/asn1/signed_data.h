// SignedData.h: interface for the CSignedData class.
//

#pragma once
#include "asn1/asn1_set_of.h"

#include "asn1/asn1_sequence.h"
#include "asn1/certificate.h"
#include "asn1/content_info.h"
#include "sign/disigonsdk.h"

class CSignedData : public CASN1Sequence {
 public:
  CSignedData(UUCBufferedReader& reader);

  CSignedData(const CASN1Object& signedData);

  CSignedData(const CASN1SetOf& algos, const CContentInfo& contentInfo,
              const CASN1SetOf& signerInfos, const CASN1SetOf& certificates);

  virtual ~CSignedData();

  CASN1SetOf getDigestAlgorithmIdentifiers();

  CContentInfo getContentInfo();

  CASN1SetOf getSignerInfos();

  CASN1SetOf getCertificates();

  CCertificate getSignerCertificate(int index);

  void makeDetached();

  void setContent(UUCByteArray& content);

  int verify(int i);

  int verify(int i, const char* dateTime, REVOCATION_INFO* pRevocationInfo);
};


