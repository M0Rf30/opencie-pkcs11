#include "asn1_boolean.h"

const BYTE CASN1Boolean::TAG = 0x01;

CASN1Boolean::~CASN1Boolean() {}

CASN1Boolean::CASN1Boolean(BufferedReader& reader) : CASN1Object(reader) {}

CASN1Boolean::CASN1Boolean(bool b) {
  setTag(TAG);
  ByteDynArray val;
  val.push(static_cast<BYTE>(b ? 0xFF : 0));
  setValue(val);
}

CASN1Boolean::CASN1Boolean(const CASN1Object& obj) : CASN1Object(obj) {
  setTag(TAG);
}

bool CASN1Boolean::getBoolValue() const { return getValue()->data()[0] == 1; }
