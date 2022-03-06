#pragma once

#include "asn1_object.h"

class CASN1OptionalField : public CASN1Object {
 public:
  CASN1OptionalField(UUCBufferedReader& reader);

  CASN1OptionalField(const CASN1Object& pAsn1Obj, const BYTE& btClass);

  CASN1OptionalField(const CASN1Object& opt);

  ~CASN1OptionalField();

  BYTE getTag() const;

 private:
  static const BYTE TAG;
  BYTE m_btClass;
};

