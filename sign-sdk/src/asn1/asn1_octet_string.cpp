// SPDX-License-Identifier: LGPL-3.0-or-later
#include "asn1_octet_string.h"

const BYTE CASN1OctetString::TAG = 0x04;

CASN1OctetString::~CASN1OctetString() {}

CASN1OctetString::CASN1OctetString(BufferedReader& reader)
    : CASN1Object(reader) {}

CASN1OctetString::CASN1OctetString(const char* szOctetString)
    : CASN1Object(TAG) {
  ByteDynArray octetString(ByteArray(
      reinterpret_cast<const BYTE*>(szOctetString), strlen(szOctetString)));
  setValue(octetString);
}

CASN1OctetString::CASN1OctetString(const ByteDynArray& octetString)
    : CASN1Object(TAG) {
  setValue(octetString);
}

CASN1OctetString::CASN1OctetString(const BYTE* value, long len)
    : CASN1Object(TAG) {
  setValue(value, len);
}

CASN1OctetString::CASN1OctetString(const CASN1Object& octetString)
    : CASN1Object(octetString) {}
