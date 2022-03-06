// RelativeDistinguishedName.h: interface for the CRelativeDistinguishedName
// class.
//

#pragma once

#include "asn1_set_of.h"
// #include "AttributeValueAssertion.h"

class CRelativeDistinguishedName : public CASN1SetOf {
 public:
  CRelativeDistinguishedName(UUCBufferedReader& reader);

  CRelativeDistinguishedName();

  CRelativeDistinguishedName(const CASN1Object& rname);

  // void addAttributeValue(const CAttributeValueAssertion& algos);

  virtual ~CRelativeDistinguishedName();
};


