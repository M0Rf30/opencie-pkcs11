// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <string>

#include "Util/byte_array.h"


class M7MParser {
 public:
  M7MParser();

  int Load(const char* m7m, int m7mlen);

  int GetP7M(UUCByteArray& p7m);

  int GetTSR(UUCByteArray& tsr);

 private:
  UUCByteArray m_p7m;
  UUCByteArray m_tsr;
};

