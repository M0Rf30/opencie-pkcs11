// ASN1BitString.cpp: implementation of the CASN1BitString class.
//

#include "asn1_bit_string.h"

// Construction/Destruction

const BYTE CASN1BitString::TAG = 0x03;

CASN1BitString::~CASN1BitString() {}

CASN1BitString::CASN1BitString(UUCBufferedReader& reader)
    : CASN1Object(reader) {}

CASN1BitString::CASN1BitString(const CASN1Object& obj) : CASN1Object(obj) {}
