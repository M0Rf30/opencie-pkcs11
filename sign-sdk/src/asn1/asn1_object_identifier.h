#pragma once

#include <string>

#include "asn1_object.h"


class CASN1ObjectIdentifier : public CASN1Object {
 private:
  const static BYTE TAG;

 public:
  CASN1ObjectIdentifier(UUCBufferedReader& reader);

  CASN1ObjectIdentifier(const CASN1Object&);

  CASN1ObjectIdentifier(const char* szObjId);

  // distruttore
  ~CASN1ObjectIdentifier();

  void ToOidString(UUCByteArray& objId);

  bool equals(const CASN1ObjectIdentifier& objid);
};

