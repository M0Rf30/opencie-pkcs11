#pragma once
#include "asn1/asn1_integer.h"
#include "asn1/asn1_sequence.h"
#include "asn1_object.h"

class CRSAPublicKey : public CASN1Sequence {
 public:
  // Costruttori
  CRSAPublicKey(UUCBufferedReader& reader);

  CRSAPublicKey(const CASN1Object& obj);

  CRSAPublicKey(const CASN1Integer& modulus, const CASN1Integer& exponent);

  virtual ~CRSAPublicKey();

  CASN1Integer getModulus();

  CASN1Integer getExponent();

 private:
};
