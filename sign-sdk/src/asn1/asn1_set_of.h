#pragma once

#include "asn1_generic_sequence.h"
#include "asn1_object.h"
#define MAX_OBJ 10

class CASN1SetOf : public CASN1GenericSequence {
 public:
  ~CASN1SetOf();

  CASN1SetOf();

  CASN1SetOf(const CASN1Object&);

 private:
  static const BYTE TAG;
};

