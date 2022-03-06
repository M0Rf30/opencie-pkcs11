// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <cstdio>

#include "csp/cie_enable.h"

using cie_change_pin_fn = CK_RV (*)(const char* szCurrentPIN, const char* szNewPIN,
                             int* attempts, PROGRESS_CALLBACK progressCallBack);

using cie_unblock_pin_fn = CK_RV (*)(const char* szPUK, const char* szNewPIN,
                              int* attempts,
                              PROGRESS_CALLBACK progressCallBack);

