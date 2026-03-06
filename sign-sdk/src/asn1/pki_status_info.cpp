// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

#include "pki_status_info.h"

CPKIStatusInfo::CPKIStatusInfo(BufferedReader& reader)
    : CASN1Sequence(reader) {}

CPKIStatusInfo::CPKIStatusInfo(const CASN1Object& pkiStatusInfo)
    : CASN1Sequence(pkiStatusInfo) {}

CPKIStatusInfo::~CPKIStatusInfo() {}

CASN1Integer CPKIStatusInfo::getStatus() { return elementAt(0); }
