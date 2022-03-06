#pragma once

#include "asn1_generic_sequence.h"

class CASN1Sequence : public CASN1GenericSequence {
 public:
  ~CASN1Sequence();

  CASN1Sequence();

  CASN1Sequence(const UUCByteArray& content);

  CASN1Sequence(UUCBufferedReader& reader);

  CASN1Sequence(const CASN1Object& obj);

  CASN1Sequence(const BYTE* value, long len);

 private:
  static const BYTE TAG;
};

