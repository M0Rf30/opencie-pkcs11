// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

/**
 * @file pin_manager.h
 * @brief CIE PIN change and unblock function-pointer types.
 *
 * Declares the function signatures for changing the CIE user PIN
 * and unblocking it using the PUK, with progress reporting.
 */

#pragma once

#include <cstdio>

#include "csp/cie_enable.h"

/** @brief Change the CIE user PIN from @p szCurrentPIN to @p szNewPIN. */
using cie_change_pin_fn = CK_RV (*)(const char* szCurrentPIN,
                                    const char* szNewPIN, int* attempts,
                                    PROGRESS_CALLBACK progressCallBack);

/** @brief Unblock the CIE PIN using the PUK and set a new PIN. */
using cie_unblock_pin_fn = CK_RV (*)(const char* szPUK, const char* szNewPIN,
                                     int* attempts,
                                     PROGRESS_CALLBACK progressCallBack);
