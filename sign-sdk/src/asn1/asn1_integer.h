#pragma once

#include "asn1_object.h"

class CASN1Integer : public CASN1Object {
 private:
  static const BYTE TAG;

 public:
  // Costruttori

  CASN1Integer(unsigned long);

  CASN1Integer(const CASN1Object& obj);

  CASN1Integer(const BYTE* pbtVal, unsigned int nLen);

  // Distruttore
  virtual ~CASN1Integer();

  int getIntValue() const;

  unsigned long getLongValue() const;
};

