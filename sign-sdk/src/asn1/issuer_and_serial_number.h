// IssuerAndSerialNumber.h: interface for the CIssuerAndSerialNumber class.
//

#pragma once

#include "asn1/asn1_integer.h"
#include "asn1/asn1_sequence.h"
#include "name.h"

class CIssuerAndSerialNumber : public CASN1Sequence {
 public:
  CIssuerAndSerialNumber(UUCBufferedReader& reader);

  CIssuerAndSerialNumber(const CASN1Object& issuerAndSerNum);

  CIssuerAndSerialNumber(const CName& issuer, const CASN1Integer& serNum,
                         bool contextSpecific);

  virtual ~CIssuerAndSerialNumber();
};


