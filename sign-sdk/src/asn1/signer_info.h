// SignerInfo.h: interface for the CSignerInfo class.
//

#pragma once
#include "asn1/asn1_set_of.h"
#include "asn1/certificate.h"
#define MAX_RSA_MODULUS_LEN 512

#include "asn1/asn1_sequence.h"
#include "asn1/asn1_utc_time.h"
#include "asn1/algorithm_identifier.h"
#include "asn1/issuer_and_serial_number.h"
#include "asn1/time_stamp_token.h"
#include "asn1_octet_string.h"
#include "sign/disigonsdk.h"

class CSignerInfo : public CASN1Sequence {
 public:
  CSignerInfo(UUCBufferedReader& reader);

  CSignerInfo(const CASN1Object& signerInfo);

  CSignerInfo(const CIssuerAndSerialNumber& issuer,
              const CAlgorithmIdentifier& digestAlgo,
              const CAlgorithmIdentifier& encAlgo,
              const CASN1OctetString& encDigest);

  void addAuthenticatedAttributes(const CASN1SetOf& attributes);
  void addUnauthenticatedAttributes(const CASN1SetOf& attributes);

  CASN1OctetString getEncryptedDigest();
  CAlgorithmIdentifier getDigestAlgorithn();
  CIssuerAndSerialNumber getIssuerAndSerialNumber();
  CASN1SetOf getAuthenticatedAttributes();
  CASN1SetOf getUnauthenticatedAttributes();

  CTimeStampToken getTimeStampToken();
  CASN1UTCTime getSigningTime();
  // CASN1ObjectIdentifier getSigningCertificateV2();
  CASN1OctetString getContentHash();

  CASN1SetOf getCountersignatures();
  void setCountersignatures(int index, CSignerInfo& countersignature);
  void addCountersignatures(CSignerInfo& countersignature);
  int getCountersignatureCount();
  bool hasTimeStampToken();

  int verifyCountersignature(int i, CASN1SetOf& certificates);
  int verifyCountersignature(int i, CASN1SetOf& certificates,
                             const char* szDateTime,
                             REVOCATION_INFO* pRevocationInfo);

  void setTimeStampToken(CTimeStampToken& tst);

  virtual ~CSignerInfo();

  static CCertificate getSignatureCertificate(CSignerInfo& signature,
                                              CASN1SetOf& certificates);

  static int verifySignature(CASN1OctetString& source, CSignerInfo& sinfo,
                             CASN1SetOf& certificates, const char* date,
                             REVOCATION_INFO* pRevocationInfo);
};


