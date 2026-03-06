#include "asn1_object_identifier.h"

#include <cmath>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

#include "buffered_reader.h"

const BYTE CASN1ObjectIdentifier::TAG = 0x06;

CASN1ObjectIdentifier::~CASN1ObjectIdentifier() {}

CASN1ObjectIdentifier::CASN1ObjectIdentifier(BufferedReader& reader)
    : CASN1Object(reader) {}

CASN1ObjectIdentifier::CASN1ObjectIdentifier(const CASN1Object& objId)
    : CASN1Object(objId) {}

CASN1ObjectIdentifier::CASN1ObjectIdentifier(const char* strObjId)
    : CASN1Object(TAG) {
  BYTE out[256];
  int nIndex = 0;
  int nVal;
  int nAux;

  std::istringstream iss(strObjId);
  std::string token;
  bool first = true;
  int firstVal = 0;

  while (std::getline(iss, token, '.')) {
    int component = std::stoi(token);
    if (first) {
      firstVal = component;
      first = false;
      continue;
    }
    if (firstVal >= 0) {
      // combine first two components: 40 * first + second
      UINT nFirst = static_cast<UINT>(40 * firstVal + component);
      if (nFirst > 0xff) throw -1;
      out[nIndex++] = static_cast<BYTE>(nFirst);
      firstVal = -1;  // mark consumed
      continue;
    }
    nVal = component;
    if (nVal == 0) {
      out[nIndex++] = 0x00;
    } else if (nVal == 1) {
      out[nIndex++] = 0x01;
    } else {
      int i = static_cast<int>(ceil(
          (log(static_cast<double>(abs(nVal))) / log(static_cast<double>(2))) /
          7));
      while (nVal != 0) {
        nAux =
            static_cast<int>(floor(nVal / pow(static_cast<float>(128), i - 1)));
        nVal =
            nVal - static_cast<int>(pow(static_cast<float>(128), i - 1) * nAux);
        if (nVal != 0) nAux |= 0x80;
        out[nIndex++] = nAux;
        i--;
      }
    }
  }

  setValue(ByteDynArray(ByteArray(out, nIndex)));
}

bool CASN1ObjectIdentifier::equals(const CASN1ObjectIdentifier& objid) {
  if (getLength() != objid.getLength()) return false;

  const BYTE* val1 = getValue()->data();
  const BYTE* val2 = objid.getValue()->data();

  int r = memcmp(val1, val2, getLength());

  return r == 0;
}

void CASN1ObjectIdentifier::ToOidString(ByteDynArray& objId) {
  long value = 0;
  bool first = true;
  char szValue[256];

  const ByteDynArray* pValue = getValue();
  int len = pValue->size();
  const BYTE* pVal = pValue->data();

  for (int i = 0; i != len; i++) {
    int b = pVal[i];

    value = value * 128 + (b & 0x7f);
    if ((b & 0x80) == 0) {  // end of number reached
      if (first) {
        switch (static_cast<int>(value) / 40) {
          case 0:
            objId.push('0');
            break;

          case 1:
            objId.push('1');
            value -= 40;
            break;
          default:
            objId.push('2');
            value -= 80;
            break;
        }
        first = false;
      }

      objId.push('.');
      snprintf(szValue, sizeof(szValue), "%ld", value);
      objId.append(
          ByteArray(reinterpret_cast<BYTE*>(szValue), strlen(szValue)));
      value = 0;
    }
  }

  objId.push(static_cast<BYTE>('\0'));
}
