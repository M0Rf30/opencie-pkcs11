#include "asn1/algorithm_identifier.h"

#include "asn1_null.h"

CAlgorithmIdentifier::CAlgorithmIdentifier(const CASN1Object& algoId)
    : CASN1Sequence(algoId) {}

CAlgorithmIdentifier::CAlgorithmIdentifier(const char* lpszObjId) {
  addElement(CASN1ObjectIdentifier(lpszObjId));
  addElement(CASN1Null());
}

CAlgorithmIdentifier::CAlgorithmIdentifier(BufferedReader& reader)
    : CASN1Sequence(reader) {}

CASN1ObjectIdentifier CAlgorithmIdentifier::getOID() {
  return CASN1ObjectIdentifier(elementAt(0));
}

CASN1Object CAlgorithmIdentifier::getParameters() {
  return elementAt(1);
}
