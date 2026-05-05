// SPDX-License-Identifier: LGPL-3.0-or-later
#include "asn1_generic_sequence.h"

#include <cstdlib>

#include "asn1_exception.h"

CASN1GenericSequence::CASN1GenericSequence(BYTE btTag)
    : m_nextOffset(0),
      m_pnOffsets(nullptr),
      m_nOffsetsMax(MAXSIZE),
      m_nSize(0) {
  m_pnOffsets = static_cast<unsigned int*>(
      calloc(m_nOffsetsMax + 2, sizeof(m_pnOffsets[0])));
  setTag(btTag);
}

CASN1GenericSequence::CASN1GenericSequence(BufferedReader& reader)
    : CASN1Object(reader),
      m_nextOffset(0),
      m_pnOffsets(nullptr),
      m_nOffsetsMax(MAXSIZE),
      m_nSize(0) {
  m_pnOffsets = static_cast<unsigned int*>(
      calloc(m_nOffsetsMax + 2, sizeof(m_pnOffsets[0])));
  m_nSize = makeOffset();
}

CASN1GenericSequence::CASN1GenericSequence(const ByteDynArray& content)
    : CASN1Object(content),
      m_nextOffset(0),
      m_pnOffsets(nullptr),
      m_nOffsetsMax(MAXSIZE),
      m_nSize(0) {
  m_pnOffsets = static_cast<unsigned int*>(
      calloc(m_nOffsetsMax + 2, sizeof(m_pnOffsets[0])));
  m_nSize = makeOffset();
}

CASN1GenericSequence::CASN1GenericSequence(const CASN1Object& obj)
    : CASN1Object(obj),
      m_nextOffset(0),
      m_pnOffsets(nullptr),
      m_nOffsetsMax(MAXSIZE),
      m_nSize(0) {
  m_pnOffsets = static_cast<unsigned int*>(
      calloc(m_nOffsetsMax + 2, sizeof(m_pnOffsets[0])));
  m_nSize = makeOffset();
}

CASN1GenericSequence::CASN1GenericSequence(const CASN1GenericSequence& obj)
    : CASN1Object(obj),
      m_nextOffset(0),
      m_pnOffsets(nullptr),
      m_nOffsetsMax(MAXSIZE),
      m_nSize(0) {
  m_pnOffsets = static_cast<unsigned int*>(
      calloc(m_nOffsetsMax + 2, sizeof(m_pnOffsets[0])));
  m_nSize = makeOffset();
}

CASN1GenericSequence::CASN1GenericSequence(const BYTE* value, long len)
    : CASN1Object(value, len),
      m_nextOffset(0),
      m_pnOffsets(nullptr),
      m_nOffsetsMax(MAXSIZE),
      m_nSize(0) {
  m_pnOffsets = static_cast<unsigned int*>(
      calloc(m_nOffsetsMax + 2, sizeof(m_pnOffsets[0])));
  m_nSize = makeOffset();
}

CASN1GenericSequence::~CASN1GenericSequence() {
  if (m_pnOffsets) free(m_pnOffsets);
  // NSLog(@"~CASN1GenericSequence()");
}

CASN1GenericSequence& CASN1GenericSequence::operator=(
    const CASN1GenericSequence& obj) {
  setValue(*obj.getValue());
  setTag(obj.getTag());
  m_nSize = makeOffset();
  return *this;
}

// cppcheck-suppress duplInheritedMember
void CASN1GenericSequence::fromByteArray(const ByteDynArray& content) {
  BufferedReader reader(content);

  fromReader(reader);
  m_nSize = makeOffset();
}

void CASN1GenericSequence::addElement(const CASN1Object& obj) {
  ByteDynArray serObj;
  obj.toByteArray(serObj);

  const ByteDynArray* pOldVal = getValue();

  if (pOldVal->size() == 0) {
    setValue(serObj);
  } else {
    ByteDynArray newVal;
    // copy old val
    newVal.append(*pOldVal);
    // copy val to add
    newVal.append(serObj);
    // set new val
    setValue(newVal);
  }

  m_nSize = makeOffset();
}

void CASN1GenericSequence::addElementAt(const CASN1Object& obj, int nPos) {
  if (nPos < 0 || static_cast<unsigned int>(nPos) > size())
    throw -1;  // new IllegalArgumentException("Invalid position:" + nPos);

  ByteDynArray serObj;
  obj.toByteArray(serObj);

  const ByteDynArray* pOldVal = getValue();

  ByteDynArray newVal;

  if (pOldVal->size() == 0) {
    newVal.append(serObj);
  } else if (nPos == 0) {
    // copy val to add
    newVal.append(serObj);
    // copy old val
    newVal.append(*pOldVal);
  } else {
    int offset = m_pnOffsets[nPos];

    // copy old val fino all'offset
    newVal.append(ByteArray(pOldVal->data(), offset));

    // copy val to add
    newVal.append(serObj);

    // copy the rest of the old val
    newVal.append(
        ByteArray(pOldVal->data() + offset, pOldVal->size() - offset));
  }

  // set new val
  setValue(newVal);

  m_nSize = makeOffset();
}

CASN1Object CASN1GenericSequence::elementAt(int nPos) {
  if (this->size() > static_cast<unsigned int>(nPos)) {
    int offset = m_pnOffsets[nPos];
    ByteDynArray curObj(
        ByteArray(getValue()->data() + offset, getLength() - offset + 1));
    CASN1Object curAsn1Obj(curObj);

    m_nextOffset = offset + curAsn1Obj.getSerializedLength();

    return curAsn1Obj;
  }
  return CASN1Object();
}

CASN1Object CASN1GenericSequence::nextElement() {
  ByteDynArray curObj(ByteArray(getValue()->data() + m_nextOffset,
                                getLength() - m_nextOffset + 1));

  CASN1Object curAsn1Obj(curObj);

  m_nextOffset += curAsn1Obj.getSerializedLength();

  return curAsn1Obj;
}

CASN1Object CASN1GenericSequence::elementAtOpt(int nPos) {
  if (this->size() > static_cast<unsigned int>(nPos)) {
    int offset = m_pnOffsets[nPos];
    CASN1Object curAsn1Obj(getValue()->data() + offset,
                           getLength() - offset + 1);

    m_nextOffset = offset + curAsn1Obj.getSerializedLength();

    return curAsn1Obj;
  }
  return CASN1Object();
}

CASN1Object CASN1GenericSequence::nextElementOpt() {
  CASN1Object curAsn1Obj(getValue()->data() + m_nextOffset,
                         getLength() - m_nextOffset + 1);

  m_nextOffset += curAsn1Obj.getSerializedLength();

  return curAsn1Obj;
}

void CASN1GenericSequence::setElementAt(const CASN1Object& obj, int nPos) {
  removeElementAt(nPos);
  addElementAt(obj, nPos);
}

void CASN1GenericSequence::removeElementAt(int nPos) {
  if (nPos < 0 || static_cast<unsigned int>(nPos) > size()) throw -1;

  ByteDynArray oldVal(*(getValue()));

  ByteDynArray newVal;

  if (oldVal.size() == 0) {
    // do nothing
  } else if (nPos == 0) {
    // elimina la prima
    int offset = m_pnOffsets[1];

    // copy the rest of the old val
    newVal.append(ByteArray(oldVal.data() + offset, oldVal.size() - offset));
  } else {
    int offset = m_pnOffsets[nPos];
    int offset1 = m_pnOffsets[nPos + 1];

    // copy old val fino all'offset
    newVal.append(ByteArray(oldVal.data(), offset));

    // copy the rest of the old val
    newVal.append(ByteArray(oldVal.data() + offset1, oldVal.size() - offset1));
  }

  // set new val
  setValue(newVal);

  m_nSize = makeOffset();
}

void CASN1GenericSequence::removeAll() {
  ByteDynArray newVal;

  // set new val
  setValue(newVal);

  m_nSize = 0;
}

bool CASN1GenericSequence::isPresent(int nPos) const {
  if (nPos < 0) throw -1;

  return static_cast<unsigned int>(nPos) < size();
}

unsigned int CASN1GenericSequence::size() const { return m_nSize; }

int CASN1GenericSequence::makeOffset() {
  const ByteDynArray* pContent = getValue();
  unsigned long len = pContent->size();

  unsigned int offset = 0;
  ByteDynArray objVal;
  unsigned int i = 0;
  while (offset < len) {
    if (i == m_nOffsetsMax) {
      m_nOffsetsMax += 1000;
      m_pnOffsets = static_cast<unsigned int*>(
          realloc(m_pnOffsets, sizeof(m_pnOffsets[0]) * m_nOffsetsMax + 2));
    }
    m_pnOffsets[i] = offset;

    // Current object
    try {
      CASN1Object currentObj(pContent->data() + offset,
                             pContent->size() - offset + 1);
      int iLen = currentObj.getOrigLenLen() + currentObj.getLength() + 2;
      offset += iLen;
      i++;
    } catch (const CASN1ParsingException& e) {
      break;
    }
  }

  return i;
}
