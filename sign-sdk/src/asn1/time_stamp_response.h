// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

/*
 *  TimeStampResponse.h
 *  iDigitalSApp
 *
 *  Created by svp on 19/03/12.
 *  Copyright 2012 __MyCompanyName__. All rights reserved.
 *
 */

#include "asn1/time_stamp_token.h"
#include "pki_status_info.h"

class CTimeStampResponse : public CASN1Sequence {
 public:
  CTimeStampResponse(UUCBufferedReader& reader);

  CTimeStampResponse(const CASN1Object& timeStampresponse);

  CTimeStampResponse(const BYTE* content, int length);

  virtual ~CTimeStampResponse();

  CTimeStampToken getTimeStampToken();

  CPKIStatusInfo getPKIStatusInfo();

  int verify(const char* szDateTime);

  int verify();
};
