// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "buffered_reader.h"

#include <algorithm>
#include <stdexcept>

BufferedReader::BufferedReader(const ByteDynArray& buffer)
    : m_buffer(buffer.data(), buffer.data() + buffer.size()),
      m_position(0),
      m_eof(false) {}

BufferedReader::BufferedReader(const BYTE* pbtBuffer, int len)
    : m_buffer(pbtBuffer, pbtBuffer + len), m_position(0), m_eof(false) {}

unsigned int BufferedReader::getPosition() const {
  return static_cast<unsigned int>(m_position);
}

void BufferedReader::setPosition(unsigned int index) {
  m_position = std::min(static_cast<size_t>(index), m_buffer.size());
}

unsigned int BufferedReader::read(BYTE* pbtBuffer, unsigned int nLen) {
  if (isAtEnd()) {
    return 0;
  }

  size_t bytesToRead = std::min(static_cast<size_t>(nLen), remainingBytes());

  std::memcpy(pbtBuffer, m_buffer.data() + m_position, bytesToRead);
  m_position += bytesToRead;

  return static_cast<unsigned int>(bytesToRead);
}

unsigned int BufferedReader::read(ByteDynArray& byteArray) {
  const size_t chunkSize = 255;
  BYTE buffer[chunkSize];
  unsigned int totalRead = 0;
  unsigned int bytesRead = 0;

  while ((bytesRead = read(buffer, chunkSize)) > 0) {
    byteArray.append(ByteArray(buffer, bytesRead));
    totalRead += bytesRead;
  }

  return totalRead;
}

void BufferedReader::mark() { m_mark_stack.push(m_position); }

void BufferedReader::reset() {
  if (!m_mark_stack.empty()) {
    m_position = m_mark_stack.top();
    m_mark_stack.pop();
  }
}

void BufferedReader::releaseMark() {
  if (!m_mark_stack.empty()) {
    m_mark_stack.pop();
  }
}

bool BufferedReader::isAtEnd() const { return m_position >= m_buffer.size(); }

size_t BufferedReader::remainingBytes() const {
  if (isAtEnd()) {
    return 0;
  }
  return m_buffer.size() - m_position;
}
