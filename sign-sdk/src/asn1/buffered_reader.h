// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file buffered_reader.h
 * @brief Modern C++ replacement for BufferedReader - ASN.1 parsing
 * infrastructure
 *
 * This class provides buffered reading capabilities essential for ASN.1/DER/BER
 * parsing with mark/reset functionality for backtracking during optional field
 * parsing.
 *
 * **Modernization Goals:**
 * - Replace raw pointer management with modern C++ containers
 * - Use RAII for automatic resource management
 * - Maintain identical interface for seamless migration
 * - Preserve all ASN.1 parsing functionality
 */

#pragma once

#include <cstring>
#include <memory>
#include <stack>
#include <vector>

#include "../../../shared/src/util/array.h"

class BufferedReader {
 public:
  // Position management
  unsigned int getPosition() const;
  void setPosition(unsigned int index);

  // Constructors - maintain compatibility with existing code
  explicit BufferedReader(const ByteDynArray& buffer);
  explicit BufferedReader(const BYTE* pbtBuffer, int len);

  // Modern C++ destructor (RAII - no manual cleanup needed)
  ~BufferedReader() = default;

  // Reading operations
  unsigned int read(BYTE* pbtBuffer, unsigned int nLen);
  unsigned int read(ByteDynArray& byteArray);

  // Mark/reset for ASN.1 backtracking during parsing
  void mark();
  void reset();
  void releaseMark();

 private:
  // Modern C++ member variables
  std::vector<BYTE> m_buffer;       // Owns buffer data (RAII)
  size_t m_position;                // Current read position
  bool m_eof;                       // End-of-buffer flag
  std::stack<size_t> m_mark_stack;  // Position stack for mark/reset

  // Helper methods
  bool isAtEnd() const;
  size_t remainingBytes() const;
};
