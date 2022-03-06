// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include "asn1/asn1_integer.h"
#include "asn1/asn1_sequence.h"
#include "sign/disigonsdk.h"

class CCrl : public CASN1Sequence {
 public:
  CCrl(UUCBufferedReader& reader);

  CCrl(const CASN1Object& contentInfo);

  bool isRevoked(const CASN1Integer& serialNumber, const char* szDateTime,
                 int* pReason, REVOCATION_INFO* pRevocationInfo);
};

