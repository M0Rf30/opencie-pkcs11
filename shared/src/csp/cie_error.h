// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file cie_error.h
 * @brief Thread-local last-error record for CIE card failures.
 *
 * Backs the public cie_classify_sw() / cie_last_error() API declared in
 * opencie/cie_ext.h. Internal callers (pin_manager.cpp, cie_enable.cpp,
 * ...) record the ISO 7816 status word (or a transport failure) here
 * instead of discarding it, so the calling thread can retrieve the
 * classified reason after a cie_* call fails.
 */

#pragma once

#include <cstdint>

#include "opencie/cie_ext.h"

/**
 * @brief Record a card failure carrying the ISO 7816 status word @p sw.
 *
 * Classifies @p sw via cie_classify_sw() and stores the result in the
 * calling thread's last-error record.
 */
void cie_record_sw_error(uint16_t sw);

/**
 * @brief Record a card failure with no usable status word (e.g. a
 * transport or Secure Messaging failure).
 */
void cie_record_transport_error();

/**
 * @brief Reset the calling thread's last-error record to CIE_ERR_NONE.
 */
void cie_clear_error();
