// CertificateInfo.h: interface for the CCertificateInfo class.

#pragma once

#include "asn1/asn1_integer.h"
#include "asn1/asn1_sequence.h"
#include "asn1/asn1_utc_time.h"
#include "asn1/algorithm_identifier.h"
#include "name.h"
#include "subject_public_key_info.h"

class CCertificateInfo : public CASN1Sequence {
 public:
  CCertificateInfo(UUCBufferedReader& reader);

  CCertificateInfo(const CASN1Object& cert);

  virtual ~CCertificateInfo();

  CASN1Integer getVersion();

  CASN1Integer getSerialNumber();

  CAlgorithmIdentifier getSignatureAlgo();

  CName getIssuer();

  CASN1UTCTime getExpiration();
  CASN1UTCTime getFrom();

  CName getSubject();

  CSubjectPublicKeyInfo getSubjectPublicKeyInfo();

  CASN1Sequence getExtensions();
};

