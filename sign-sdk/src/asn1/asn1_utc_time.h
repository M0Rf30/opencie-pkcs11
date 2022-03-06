// ASN1UTCTime.h: interface for the CASN1UTCTime class.
//

#pragma once

#include "asn1_object.h"

class CASN1UTCTime : public CASN1Object {
 public:
 private:
  static const BYTE TAG;

 public:
  // Costruttori
  CASN1UTCTime(UUCBufferedReader& reader);

  CASN1UTCTime(const char* szUTCTime);

  CASN1UTCTime(const CASN1Object& obj);

  // Distruttore
  virtual ~CASN1UTCTime();

  void getUTCTime(char* szTime);
};


