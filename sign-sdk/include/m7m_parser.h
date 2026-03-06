// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

/**
 * @file m7m_parser.h
 * @brief Parser for .m7m (marked) files containing a P7M envelope and a TSR
 * timestamp.
 */

#pragma once

#include <string>

#include "util/array.h"

/**
 * Parses Italian .m7m (marked) archive files that bundle a CAdES .p7m
 * signature with an RFC 3161 timestamp response (.tsr).
 */
class M7MParser {
 public:
  M7MParser();

  /** Parse the .m7m data from a memory buffer. */
  int Load(const char* m7m, int m7mlen);

  /** Extract the embedded PKCS#7 signed data. */
  int GetP7M(ByteDynArray& p7m);

  /** Extract the embedded timestamp response. */
  int GetTSR(ByteDynArray& tsr);

 private:
  ByteDynArray m_p7m;
  ByteDynArray m_tsr;
};
