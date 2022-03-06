// ASN1BitString.h: interface for the CASN1BitString class.
//

#pragma once

#include "asn1_object.h"

class CASN1BitString : public CASN1Object {
 public:
  // Costruttori
  CASN1BitString(UUCBufferedReader& reader);

  CASN1BitString(const CASN1Object& obj);

  // Distruttore
  virtual ~CASN1BitString();

 private:
  static const BYTE TAG;
};

