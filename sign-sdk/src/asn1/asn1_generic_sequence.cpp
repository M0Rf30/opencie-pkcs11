// SPDX-License-Identifier: LGPL-3.0-or-later
#include "asn1_generic_sequence.h"

#include <cstdlib>

#include "asn1_exception.h"

namespace {
// calloc()/realloc() can fail for a pathologically large offset table;
// treat that the same as any other unparseable input instead of handing
// back or writing through a null pointer.
unsigned int* allocOffsets(unsigned int count) {
  void* p = calloc(count, sizeof(unsigned int));
  if (!p) {
    throw CASN1ParsingException();
  }
  return static_cast<unsigned int*>(p);
}

// Returns the total encoded size (tag + length octets + value) of the TLV
// starting at `data`, without copying or parsing its value -- or 0 if that
// cannot be determined from the `available` bytes (indefinite length,
// truncated header, or a length that would read past `available`).
//
// Every CASN1Object/BufferedReader constructor that takes a pointer+length
// copies the *entire* span handed to it up front (BufferedReader owns a
// std::vector<BYTE> copy of its input; see buffered_reader.cpp). The
// element accessors below used to hand such constructors "everything from
// this element's offset to the end of the sequence's content" instead of
// just this element's own span, so walking a SEQUENCE of N elements from
// front to back copied ~N, ~N-1, ~N-2, ... elements' worth of trailing
// bytes -- an O(N^2) copy storm that is negligible for a handful of
// certificate extensions but catastrophic for e.g. a CRL with hundreds of
// thousands of revokedCertificates entries (multi-minute hangs on a
// multi-hundred-megabyte "remaining buffer" copied per entry). Bounding
// the span to just this element's own encoded length restores O(N) total
// cost for a full sequential scan, with identical parse results for
// well-formed DER.
size_t PeekTlvSpan(const BYTE* data, size_t available) {
  if (available < 2) return 0;

  size_t pos = 1;  // tag octet
  BYTE lenByte = data[pos++];
  size_t valueLen;

  if (lenByte == 0x80) {
    return 0;  // indefinite length (BER): let the caller fall back
  } else if (lenByte & 0x80) {
    size_t nLenOctets = lenByte & 0x7F;
    if (nLenOctets == 0 || nLenOctets > sizeof(unsigned int) ||
        pos + nLenOctets > available) {
      return 0;
    }
    valueLen = 0;
    for (size_t i = 0; i < nLenOctets; i++)
      valueLen = (valueLen << 8) | data[pos++];
  } else {
    valueLen = lenByte;
  }

  size_t total = pos + valueLen;
  if (total < pos || total > available) return 0;  // overflow or truncated
  return total;
}
}  // namespace

CASN1GenericSequence::CASN1GenericSequence(BYTE btTag)
    : m_nextOffset(0),
      m_pnOffsets(nullptr),
      m_nOffsetsMax(MAXSIZE),
      m_nSize(0) {
  m_pnOffsets = allocOffsets(m_nOffsetsMax + 2);
  setTag(btTag);
}

CASN1GenericSequence::CASN1GenericSequence(BufferedReader& reader)
    : CASN1Object(reader),
      m_nextOffset(0),
      m_pnOffsets(nullptr),
      m_nOffsetsMax(MAXSIZE),
      m_nSize(0) {
  m_pnOffsets = allocOffsets(m_nOffsetsMax + 2);
  m_nSize = makeOffset();
}

CASN1GenericSequence::CASN1GenericSequence(const ByteDynArray& content)
    : CASN1Object(content),
      m_nextOffset(0),
      m_pnOffsets(nullptr),
      m_nOffsetsMax(MAXSIZE),
      m_nSize(0) {
  m_pnOffsets = allocOffsets(m_nOffsetsMax + 2);
  m_nSize = makeOffset();
}

CASN1GenericSequence::CASN1GenericSequence(const CASN1Object& obj)
    : CASN1Object(obj),
      m_nextOffset(0),
      m_pnOffsets(nullptr),
      m_nOffsetsMax(MAXSIZE),
      m_nSize(0) {
  m_pnOffsets = allocOffsets(m_nOffsetsMax + 2);
  m_nSize = makeOffset();
}

CASN1GenericSequence::CASN1GenericSequence(const CASN1GenericSequence& obj)
    : CASN1Object(obj),
      m_nextOffset(0),
      m_pnOffsets(nullptr),
      m_nOffsetsMax(MAXSIZE),
      m_nSize(0) {
  m_pnOffsets = allocOffsets(m_nOffsetsMax + 2);
  m_nSize = makeOffset();
}

CASN1GenericSequence::CASN1GenericSequence(const BYTE* value, long len)
    : CASN1Object(value, len),
      m_nextOffset(0),
      m_pnOffsets(nullptr),
      m_nOffsetsMax(MAXSIZE),
      m_nSize(0) {
  m_pnOffsets = allocOffsets(m_nOffsetsMax + 2);
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
    throw logged_error("CASN1GenericSequence: invalid position");

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
    size_t available = getLength() - offset;
    size_t span = PeekTlvSpan(getValue()->data() + offset, available);
    if (span == 0) span = available;
    ByteDynArray curObj(ByteArray(getValue()->data() + offset, span));
    CASN1Object curAsn1Obj(curObj);

    m_nextOffset = offset + curAsn1Obj.getSerializedLength();

    return curAsn1Obj;
  }
  return CASN1Object();
}

CASN1Object CASN1GenericSequence::nextElement() {
  if (m_nextOffset > getLength()) {
    throw CASN1ParsingException();
  }

  size_t available = getLength() - m_nextOffset;
  size_t span = PeekTlvSpan(getValue()->data() + m_nextOffset, available);
  if (span == 0) span = available;
  ByteDynArray curObj(ByteArray(getValue()->data() + m_nextOffset, span));

  CASN1Object curAsn1Obj(curObj);

  m_nextOffset += curAsn1Obj.getSerializedLength();

  return curAsn1Obj;
}

CASN1Object CASN1GenericSequence::elementAtOpt(int nPos) {
  if (this->size() > static_cast<unsigned int>(nPos)) {
    int offset = m_pnOffsets[nPos];
    size_t available = getLength() - offset;
    size_t span = PeekTlvSpan(getValue()->data() + offset, available);
    if (span == 0) span = available;
    CASN1Object curAsn1Obj(getValue()->data() + offset,
                           static_cast<long>(span));

    m_nextOffset = offset + curAsn1Obj.getSerializedLength();

    return curAsn1Obj;
  }
  return CASN1Object();
}

CASN1Object CASN1GenericSequence::nextElementOpt() {
  if (m_nextOffset > getLength()) {
    throw CASN1ParsingException();
  }

  size_t available = getLength() - m_nextOffset;
  size_t span = PeekTlvSpan(getValue()->data() + m_nextOffset, available);
  if (span == 0) span = available;
  CASN1Object curAsn1Obj(getValue()->data() + m_nextOffset,
                         static_cast<long>(span));

  m_nextOffset += curAsn1Obj.getSerializedLength();

  return curAsn1Obj;
}

void CASN1GenericSequence::setElementAt(const CASN1Object& obj, int nPos) {
  removeElementAt(nPos);
  addElementAt(obj, nPos);
}

void CASN1GenericSequence::removeElementAt(int nPos) {
  if (nPos < 0 || static_cast<unsigned int>(nPos) > size())
    throw logged_error("CASN1GenericSequence: invalid position");

  ByteDynArray oldVal(*(getValue()));

  ByteDynArray newVal;

  if (oldVal.size() == 0) {
    // do nothing
  } else if (nPos == 0) {
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
  if (nPos < 0) throw logged_error("CASN1GenericSequence: invalid position");

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
      unsigned int* pNew = static_cast<unsigned int*>(
          realloc(m_pnOffsets, sizeof(m_pnOffsets[0]) * (m_nOffsetsMax + 2)));
      if (!pNew) {
        throw CASN1ParsingException();
      }
      m_pnOffsets = pNew;
    }
    m_pnOffsets[i] = offset;

    // Current object
    try {
      size_t available = pContent->size() - offset;
      size_t span = PeekTlvSpan(pContent->data() + offset, available);
      if (span == 0) span = available;
      CASN1Object currentObj(pContent->data() + offset,
                             static_cast<long>(span));
      int iLen = currentObj.getOrigLenLen() + currentObj.getLength() + 2;
      offset += iLen;
      i++;
    } catch (const CASN1ParsingException& e) {
      break;
    }
  }

  return i;
}
