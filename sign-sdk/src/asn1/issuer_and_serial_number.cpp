// IssuerAndSerialNumber.cpp: implementation of the CIssuerAndSerialNumber
// class.
//

#include "asn1/issuer_and_serial_number.h"

#include "asn1_optional_field.h"

CIssuerAndSerialNumber::CIssuerAndSerialNumber(BufferedReader& reader)
    : CASN1Sequence(reader) {}

CIssuerAndSerialNumber::CIssuerAndSerialNumber(
    const CASN1Object& issuerAndSerNum)
    : CASN1Sequence(issuerAndSerNum) {}

CIssuerAndSerialNumber::CIssuerAndSerialNumber(const CName& issuer,
                                               const CASN1Integer& serNum,
                                               bool contextSpecific) {
  if (contextSpecific) {
    CASN1Sequence issuerField;
    issuerField.addElement(issuer);

    CASN1Sequence innerSequence;
    innerSequence.addElement(CASN1OptionalField(issuerField, 0x04));

    addElement(innerSequence);
    addElement(serNum);
  } else {
    addElement(issuer);
    addElement(serNum);
  }
}

CIssuerAndSerialNumber::~CIssuerAndSerialNumber() {}
