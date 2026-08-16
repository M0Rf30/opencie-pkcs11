// SPDX-License-Identifier: LGPL-3.0-or-later
#include "asn1_object.h"

#include <memory.h>

#include <vector>

#include "asn1_exception.h"
#include "util/util.h"

CASN1Object::CASN1Object()
    : m_btTag(0), m_indefiniteLen(false), m_btLenRead(0) {}

CASN1Object::CASN1Object(const CASN1Object& obj)
    : m_btTag(obj.getTag()), m_indefiniteLen(false), m_btLenRead(0) {
  m_value.append(*(obj.getValue()));
}

CASN1Object::CASN1Object(BYTE btTag, const ByteDynArray& value)
    : m_btTag(btTag), m_indefiniteLen(false), m_btLenRead(0) {
  m_value.append(value);
}

CASN1Object::CASN1Object(BYTE btTag)
    : m_btTag(btTag), m_indefiniteLen(false), m_btLenRead(0) {}

CASN1Object::CASN1Object(BufferedReader& reader)
    : m_indefiniteLen(false), m_btLenRead(0) {
  fromReader(reader);
}

CASN1Object::CASN1Object(const ByteDynArray& content)
    : m_indefiniteLen(false), m_btLenRead(0) {
  fromByteArray(content);
}

CASN1Object::CASN1Object(const BYTE* value, long len)
    : m_indefiniteLen(false), m_btLenRead(0) {
  BufferedReader reader(value, len);
  fromReader(reader);
}

CASN1Object::~CASN1Object() {}

BYTE CASN1Object::getOrigLenLen() const { return m_btLenRead; }

BYTE CASN1Object::getTag() const { return m_btTag; }

void CASN1Object::setTag(BYTE tag) { m_btTag = tag; }

UINT CASN1Object::getLength() const { return m_value.size(); }

const ByteDynArray* CASN1Object::getValue() const { return &m_value; }

void CASN1Object::setValue(const ByteDynArray& value) {
  m_value.clear();

  if (value.size() > 0) {
    m_value.append(value);
  }
}

void CASN1Object::setValue(const BYTE* value, long len) {
  m_value.clear();

  if (len > 0) {
    m_value.append(ByteArray(value, len));
  }
}

int CASN1Object::getSerializedLength() {
  return getSerializedLength(m_value.size(), m_indefiniteLen);
}

int CASN1Object::getSerializedLength(int nLen, bool indefiniteLen) {
  // int nLen = getLength();
  int nTLVLen;

  if (nLen < 0x80) {
    nTLVLen = 2 + nLen;
  } else if (indefiniteLen) {
    nTLVLen = nLen + 4;
  } else {           // (nLen > 0x80)
    int nLenNeeded;  // = (int)(ceil((log((double)nLen) / log((double)2)) / 8));
    int nAuxLen = nLen;
    for (nLenNeeded = 0; nAuxLen > 0; nLenNeeded++, nAuxLen >>= 8) {
    }
    nTLVLen = 2 + nLenNeeded + nLen;
  }

  return nTLVLen;
}

CASN1Object CASN1Object::operator=(const CASN1Object& obj) {
  setValue(*obj.getValue());
  setTag(obj.getTag());
  m_btLenRead = obj.m_btLenRead;
  return CASN1Object(obj);
}

bool CASN1Object::operator==(const CASN1Object& obj) const {
  if (getTag() != obj.getTag()) return false;

  if (getLength() != obj.getLength()) return false;

  const BYTE* val1 = getValue()->data();
  const BYTE* val2 = obj.getValue()->data();
  int r = memcmp(static_cast<const void*>(val1), static_cast<const void*>(val2),
                 getLength());
  return r == 0;
}

bool CASN1Object::operator!=(const CASN1Object& obj) const {
  return (!operator==(obj));
}

void CASN1Object::toByteArray(ByteDynArray& byteArray) const {
  // ByteDynArray serializedForm;
  std::vector<BYTE> serialized;
  int nTLVLen;
  unsigned int nLen = getLength();

  // if (nLen < 0x00000080)
  //{
  //  indefinite length
  // To Do
  // }
  if (nLen < 0x80) {
    // Short Form
    nTLVLen = 2 + nLen;
    serialized.resize(nTLVLen + 1);

    serialized[0] = getTag();
    serialized[1] = static_cast<BYTE>(nLen);

    memcpy((serialized.data() + 2), getValue()->data(), nLen);

  } else {  // if (nLen >= 0x80)
    // Long Form
    // int nLenNeeded = (int)(ceil((log((double)nLen) / log((double)2)) / 8));
    int nLenNeeded = 0;
    int nAuxLen = nLen;
    for (nLenNeeded = 0; nAuxLen > 0; nLenNeeded++, nAuxLen >>= 8) {
    }

    nTLVLen = 2 + nLenNeeded + nLen;

    serialized.resize(nTLVLen);

    serialized[0] = getTag();
    serialized[1] = static_cast<BYTE>(0x80 + nLenNeeded);
    int i = 0;
    int nAux = nLen;
    for (i = 0; i < nLenNeeded; i++) {
      int nDigit = nAux;
      serialized[2 + (nLenNeeded - i - 1)] = static_cast<BYTE>(nDigit);
      nAux = nAux / 256;
    }

    memcpy((serialized.data() + 2 + (nLenNeeded)), getValue()->data(), nLen);
  }

  byteArray.append(ByteArray(serialized.data(), nTLVLen));

  // return serializedForm;
}

void CASN1Object::fromByteArray(const ByteDynArray& content) {
  BufferedReader reader(content);

  fromReader(reader);
}

void CASN1Object::fromByteArray(const BYTE* pContent, int iLen) {
  BufferedReader reader(pContent, iLen);

  fromReader(reader);
}

void CASN1Object::fromReader(BufferedReader& reader) {
  CASN1Object::parseLen(reader, &m_btTag, &m_value, &m_btLenRead, nullptr);
}

int CASN1Object::parseLen(BufferedReader& reader, BYTE* pbtTag,
                          ByteDynArray* pValue, BYTE* pbtLenRead,
                          bool* pbIndefiniteLen) {
  BYTE btTag = 0;
  BYTE btLenRead;
  UINT nLen = 0;
  BYTE btHexLen[sizeof(UINT)];
  if (pbIndefiniteLen) *pbIndefiniteLen = false;

  if (pbtLenRead) *pbtLenRead = 0;
  if (!pbtTag) pbtTag = &btTag;

  // Read Tag
  if (!reader.read(pbtTag, 1)) throw CASN1ObjectNotFoundException("");

  // Read Len
  if (!reader.read(&btLenRead, 1)) throw CASN1ParsingException();

  if (btLenRead == 0x80) {  // indefinite-length
    ByteDynArray buffer;

    parseBER(reader, buffer);

    if (pValue) pValue->append(ByteArray(buffer.data(), buffer.size()));

    if (pbIndefiniteLen) *pbIndefiniteLen = true;

    if (pbtLenRead) *pbtLenRead = 0;
    return buffer.size();
  } else if ((btLenRead & 0x80) == 0x80) {
    // Long Form
    btLenRead = btLenRead & 0x7F;

    // A length-octet count that cannot fit the UINT accumulator (or the
    // fixed staging buffer) is not representable; reject it outright
    // instead of reading it and truncating the result silently.
    if (btLenRead == 0 || btLenRead > sizeof(btHexLen)) {
      throw CASN1ParsingException();
    }

    if (reader.read(btHexLen, btLenRead) != btLenRead) {
      throw CASN1ParsingException();
    }

    for (BYTE i = 0; i < btLenRead; i++) {
      nLen = (nLen << 8) | btHexLen[i];
    }

    if (pbtLenRead) *pbtLenRead = btLenRead;
  } else {
    // Short Form
    nLen = btLenRead & 0x000000FF;
    if (pbtLenRead) *pbtLenRead = 0;
  }

  // read the rest of the value

  if (pValue) {
    // Stream the declared length in small, fixed-size chunks instead of
    // committing to one allocation sized by an unvalidated, attacker-chosen
    // length: a bogus length now fails as soon as the input is exhausted,
    // rather than after an up-to-4GiB allocation.
    constexpr unsigned int kReadChunk = 8192;
    std::vector<BYTE> pbtVal;
    std::vector<BYTE> chunk(kReadChunk);
    UINT remaining = nLen;
    while (remaining > 0) {
      unsigned int toRead = (remaining < kReadChunk) ? remaining : kReadChunk;
      unsigned int got = reader.read(chunk.data(), toRead);
      if (got == 0) {
        throw CASN1ParsingException();
      }
      pbtVal.insert(pbtVal.end(), chunk.data(), chunk.data() + got);
      remaining -= got;
    }

    pValue->append(ByteArray(pbtVal.data(), pbtVal.size()));
  }
  return nLen;
}

const char* CASN1Object::toHexString() {
  toByteArray(m_der);
  m_hexStr = dumpHexData(m_der);
  return m_hexStr.c_str();
}

namespace {
// BER indefinite-length content can nest arbitrarily (an indefinite-length
// object embedded inside another) and CASN1Object::parseBER also recurses
// once per sibling element within a single indefinite-length container.
// Both forms consume a stack frame per call, so an attacker controlling a
// couple of bytes per level can exhaust the stack. Cap the combined
// recursion depth well above anything a legitimate CMS/X.509 structure
// needs.
constexpr int kMaxAsn1BerDepth = 64;
thread_local int g_asn1BerDepth = 0;

class Asn1BerDepthGuard {
 public:
  Asn1BerDepthGuard() {
    if (++g_asn1BerDepth > kMaxAsn1BerDepth) {
      --g_asn1BerDepth;
      throw CASN1ParsingException();
    }
  }
  ~Asn1BerDepthGuard() { --g_asn1BerDepth; }
  Asn1BerDepthGuard(const Asn1BerDepthGuard&) = delete;
  Asn1BerDepthGuard& operator=(const Asn1BerDepthGuard&) = delete;
};
}  // namespace

int CASN1Object::parseBER(BufferedReader& reader, ByteDynArray& buffer) {
  Asn1BerDepthGuard depthGuard;

  int begin = reader.getPosition();

  CASN1Object obj(reader);

  int end = reader.getPosition();

  obj.toByteArray(buffer);

  BYTE btEnd[2];

  // reader.mark();

  if (reader.read(btEnd, 2) < 2) {
    throw CASN1ParsingException();
  }

  if (btEnd[0] == 0x00 && btEnd[1] == 0x00) {
    return end - begin;
  } else {
    reader.setPosition(end);  // reset();
    return end - begin +
           parseBER(reader, buffer);  // (reader).getSerializedLength();
  }
}
