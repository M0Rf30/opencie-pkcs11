// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

#include "buffered_reader.h"

#include <cstdlib>

#define MAX_BUF 2000
#define MAX_STACK_SIZE 100

// Construction/Destruction
UUCBufferedReader::UUCBufferedReader(const UUCByteArray& buffer) {
  m_pbtBuffer = const_cast<BYTE*>(buffer.getContent());
  m_nBufLen = buffer.getLength();

  m_nBufPos = 0;
  m_nIndex = 0;
  m_bEOF = true;
  m_pnStack =
      static_cast<unsigned int*>(realloc(nullptr, MAX_STACK_SIZE * sizeof(unsigned int)));
  m_nStackSize = MAX_STACK_SIZE;
  m_nTop = -1;
}

UUCBufferedReader::UUCBufferedReader(const BYTE* pbtBuffer, int len)
    : m_pbtBuffer(nullptr) {
  m_pbtBuffer = const_cast<BYTE*>(pbtBuffer);
  m_nBufLen = len;

  m_nBufPos = 0;
  m_nIndex = 0;
  m_bEOF = true;
  m_pnStack =
      static_cast<unsigned int*>(realloc(nullptr, MAX_STACK_SIZE * sizeof(unsigned int)));
  m_nStackSize = MAX_STACK_SIZE;
  m_nTop = -1;
}

UUCBufferedReader::~UUCBufferedReader() {
  try {
    free(m_pnStack);
  } catch (...) {
  }
}

unsigned int UUCBufferedReader::read(BYTE* pbtBuffer, unsigned int nLen) {
  int nRead = 0;
  if (m_nIndex + nLen > m_nBufLen) {
    if (!m_bEOF) {
      return read(pbtBuffer, nLen);
    } else {
      memcpy(pbtBuffer, m_pbtBuffer + m_nIndex, (m_nBufLen - m_nIndex));
      nRead = (m_nBufLen - m_nIndex);
      m_nIndex += nRead;
    }
  } else {
    memcpy(pbtBuffer, m_pbtBuffer + m_nIndex, nLen);
    nRead = nLen;
    m_nIndex += nRead;
  }

  return nRead;
}

unsigned int UUCBufferedReader::read(UUCByteArray& byteArray) {
  BYTE pbtBuf[255];
  unsigned int nRead = 0;
  unsigned int nCount = 0;
  while ((nRead = read(pbtBuf, 255)) != 0) {
    byteArray.append(pbtBuf, nRead);
    nCount += nRead;
  }

  nCount += nRead;
  byteArray.append(pbtBuf, nRead);

  return nCount;
}

void UUCBufferedReader::mark() {
  m_nTop++;
  if (m_nTop >= m_nStackSize) {
    m_nStackSize += MAX_STACK_SIZE;
    m_pnStack =
        static_cast<unsigned int*>(realloc(m_pnStack, m_nStackSize * sizeof(unsigned int)));
  }

  m_pnStack[m_nTop] = m_nIndex;
}

void UUCBufferedReader::releaseMark() {
  if (m_nTop > 0) {
    m_nTop--;
  }
}

void UUCBufferedReader::reset() {
  if (static_cast<int>(m_nTop) > -1) {
    m_nIndex = m_pnStack[m_nTop];
    m_nTop--;
  }
}

unsigned int UUCBufferedReader::getPosition() { return m_nIndex; }

void UUCBufferedReader::setPosition(unsigned int index) { m_nIndex = index; }
