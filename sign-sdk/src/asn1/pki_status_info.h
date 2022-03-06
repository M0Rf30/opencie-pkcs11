// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

/*
 *  PKIStatusInfo.h
 *  iDigitalSApp
 *
 *  Created by svp on 19/03/12.
 *  Copyright 2012 __MyCompanyName__. All rights reserved.
 *
 */

#include "asn1/asn1_integer.h"
#include "asn1/asn1_object.h"
#include "asn1/asn1_sequence.h"
#include "asn1/buffered_reader.h"
class CPKIStatusInfo : public CASN1Sequence {
 public:
  CPKIStatusInfo(UUCBufferedReader& reader);

  CPKIStatusInfo(const CASN1Object& PKIStatusInfo);

  virtual ~CPKIStatusInfo();

  CASN1Integer getStatus();
};

