#pragma once

#include "asn1_object.h"

class CASN1OctetString : public CASN1Object {
 private:
  const static BYTE TAG;

 public:
  // Costruttore
  CASN1OctetString(UUCBufferedReader& reader);

  CASN1OctetString(const UUCByteArray& bOctetString);

  CASN1OctetString(const char* szOctetString);

  CASN1OctetString(const CASN1Object& octetString);

  CASN1OctetString(const BYTE* value, long len);

  // Distruttore
  ~CASN1OctetString();
};

