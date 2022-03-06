// SubjectPublicKeyInfo.h: interface for the CSubjectPublicKeyInfo class.
//

#pragma once

#include "asn1/asn1_sequence.h"
#include "asn1/algorithm_identifier.h"
#include "asn1_bit_string.h"

class CSubjectPublicKeyInfo : public CASN1Sequence {
 public:
  CSubjectPublicKeyInfo(UUCBufferedReader& reader);

  CSubjectPublicKeyInfo(const CASN1Object& obj);

  virtual ~CSubjectPublicKeyInfo();

  CAlgorithmIdentifier getAlgorithmIdentifier();

  CASN1BitString getPublicKey();
};


