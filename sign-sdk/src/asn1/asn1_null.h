#pragma once
#include "asn1_object.h"

class CASN1Null : public CASN1Object {
 private:
  static const BYTE TAG;

 public:
  // costruttori
  CASN1Null(UUCBufferedReader& reader);

  CASN1Null();

  // distruttori

  ~CASN1Null();
};

