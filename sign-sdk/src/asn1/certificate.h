// Certificate.h: interface for the CCertificate class.
//

#pragma once

#include "asn1/asn1_sequence.h"
#include "asn1/asn1_utc_time.h"
#include "asn1/algorithm_identifier.h"
#include "asn1_octet_string.h"
#include "certificate_info.h"
#include "sign/disigonsdk.h"

class CCertificate : public CASN1Sequence {
 public:
  CCertificate(UUCBufferedReader& reader);

  CCertificate(const BYTE* value, long len);

  CCertificate(const CASN1Object& cert);

  virtual ~CCertificate();

  CCertificateInfo getCertificateInfo();

  CAlgorithmIdentifier getAlgorithmIdentifier();

  CASN1OctetString getAuthorithyKeyIdentifier();
  CASN1OctetString getSubjectKeyIdentifier();

  CASN1Sequence getCertificatePolicies();

  CASN1Sequence getQCStatements();

  bool isNonRepudiation();

  int verifyStatus(REVOCATION_INFO* pRevocationInfo);
  int verifyStatus(const char* szTime, REVOCATION_INFO* pRevocationInfo);
  bool verifySignature(CCertificate& cert);
  int verify();

  CName getIssuer();
  CASN1Integer getSerialNumber();
  CName getSubject();

  CASN1UTCTime getExpiration();
  CASN1UTCTime getFrom();

  CASN1Sequence getExtensions();

  bool isQualified();
  bool isValid();
  bool isValid(const char* szDateTime);
  bool isSHA256();
  CASN1Sequence getExtension(const CASN1ObjectIdentifier& oid);

  static CCertificate* createCertificate(UUCByteArray& contentArray);
};

