// SPDX-License-Identifier: LGPL-3.0-or-later
#include "asn1_set_of.h"

const BYTE CASN1SetOf::TAG = 0x31;

CASN1SetOf::CASN1SetOf() : CASN1GenericSequence(TAG) {}

CASN1SetOf::CASN1SetOf(BufferedReader& reader) : CASN1GenericSequence(reader) {}

CASN1SetOf::CASN1SetOf(const CASN1Object& obj) : CASN1GenericSequence(obj) {
  setTag(TAG);
}

CASN1SetOf::~CASN1SetOf() {}
