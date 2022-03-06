#pragma once

#include "asn1/asn1_sequence.h"
#include "asn1_object_identifier.h"

class CAlgorithmIdentifier : public CASN1Sequence {
 public:
  CAlgorithmIdentifier(const CASN1Object& algoId);

  CAlgorithmIdentifier(UUCBufferedReader& reader);

  CAlgorithmIdentifier(const char* szObjId);

  CAlgorithmIdentifier(const CASN1ObjectIdentifier& objId);

  CASN1ObjectIdentifier getOID();

  CASN1Object getParameters();
};

