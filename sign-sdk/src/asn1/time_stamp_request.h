// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

/*
 *  TimeStampRequest.h
 *  iDigitalSApp
 *
 *  Created by svp on 22/03/12.
 *  Copyright 2012 __MyCompanyName__. All rights reserved.
 *
 */

#include "asn1/time_stamp_token.h"

class CTimeStampRequest : public CASN1Sequence {
 public:
  CTimeStampRequest(UUCBufferedReader& reader);

  CTimeStampRequest(const CASN1Object& timeStampToken);

  CTimeStampRequest(const char* szHashAlgoOID, UUCByteArray& digest,
                    const char* szPolicyOID, CASN1Integer& nounce);

  virtual ~CTimeStampRequest();
};
