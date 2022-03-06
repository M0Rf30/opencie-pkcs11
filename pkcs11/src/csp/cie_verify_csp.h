// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <cstdio>

#include "cie_enable.h"
#include "sign/cie_verify.h"

using cie_verify_fn = CK_RV (*)(const char* inFilePath);
using cie_get_sign_count_fn = CK_RV (*)();
using cie_get_verify_info_fn = CK_RV (*)(int index, struct verifyInfo_t* vInfos);
using cie_extract_p7m_fn = CK_RV (*)(const char* inFilePath, const char* outFilePath);
