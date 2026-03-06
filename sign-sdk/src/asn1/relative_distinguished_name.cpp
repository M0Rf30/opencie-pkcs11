// RelativeDistinguishedName.cpp: implementation of the
// CRelativeDistinguishedName class.
//

#include "relative_distinguished_name.h"
// #include "asn1_exception.h"

CRelativeDistinguishedName::CRelativeDistinguishedName() {}

CRelativeDistinguishedName::CRelativeDistinguishedName(BufferedReader& reader)
    : CASN1SetOf(reader) {}

CRelativeDistinguishedName::CRelativeDistinguishedName(const CASN1Object& name)
    : CASN1SetOf(name) {}

/*
void CRelativeDistinguishedName::addAttributeValue(const
CAttributeValueAssertion& value)
{
        addElement(new CAttributeValueAssertion(value));
}
*/

CRelativeDistinguishedName::~CRelativeDistinguishedName() {}
