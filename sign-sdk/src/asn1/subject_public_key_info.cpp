// SubjectPublicKeyInfo.cpp: implementation of the CSubjectPublicKeyInfo class.
//

#include "subject_public_key_info.h"

// Construction/Destruction

CSubjectPublicKeyInfo::CSubjectPublicKeyInfo(UUCBufferedReader& reader)
    : CASN1Sequence(reader) {}

CSubjectPublicKeyInfo::CSubjectPublicKeyInfo(const CASN1Object& subPubKey)
    : CASN1Sequence(subPubKey) {}

CSubjectPublicKeyInfo::~CSubjectPublicKeyInfo() {}

CAlgorithmIdentifier CSubjectPublicKeyInfo::getAlgorithmIdentifier() {
  return elementAt(0);
}

CASN1BitString CSubjectPublicKeyInfo::getPublicKey() { return elementAt(1); }
