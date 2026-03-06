// SPDX-License-Identifier: LGPL-3.0-or-later
#include "asn1_null.h"

const BYTE CASN1Null::TAG = 0x05;

CASN1Null::~CASN1Null() {}

CASN1Null::CASN1Null(BufferedReader& reader) : CASN1Object(reader) {}

CASN1Null::CASN1Null() : CASN1Object(TAG) {}
