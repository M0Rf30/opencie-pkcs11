// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file cie_enable.h
 * @brief CIE card enabling/disabling API and PC/SC APDU transport callback.
 *
 * Declares the function-pointer types used by the external-facing CIE
 * enable/disable/is-enabled API, along with progress and completion
 * callbacks for asynchronous operations.  Also provides the low-level
 * APDU transmit callback used by the token transport layer.
 */

#include "pcsc/pcsc.h"
#include "pkcs11/cryptoki.h"
#include "util/definitions.h"

#ifndef SCARD_ATTR_VALUE
#define SCARD_ATTR_VALUE(Class, Tag) \
  ((((uint32_t)(Class)) << 16) | ((uint32_t)(Tag)))
#endif
#ifndef SCARD_CLASS_ICC_STATE
#define SCARD_CLASS_ICC_STATE 9 /**< ICC State specific definitions */
#endif
#ifndef SCARD_ATTR_ATR_STRING
#define SCARD_ATTR_ATR_STRING             \
  SCARD_ATTR_VALUE(SCARD_CLASS_ICC_STATE, \
                   0x0303) /**< Answer to reset (ATR) string. */
#endif

/** @brief Application callback reporting operation progress (0-100). */
typedef CK_CALLBACK_FUNCTION(CK_RV, PROGRESS_CALLBACK)(const int progress,
                                                       const char* szMessage);

/** @brief Application callback invoked when CIE enabling completes
 * successfully. */
typedef CK_CALLBACK_FUNCTION(CK_RV, COMPLETED_CALLBACK)(const char* szPan,
                                                        const char* szName,
                                                        const char* ef_seriale);

/** @brief Enable a CIE card identified by its PAN, requiring PIN verification.
 */
using cie_enable_fn = CK_RV (*)(const char* szPAN, const char* szPIN,
                                int* attempts,
                                PROGRESS_CALLBACK progressCallBack,
                                COMPLETED_CALLBACK completedCallBack);

/** @brief Check whether a CIE card identified by its PAN is already enabled. */
using cie_is_enabled_fn = CK_RV (*)(const char* szPAN);

/** @brief Disable a previously enabled CIE card. */
using cie_disable_fn = CK_RV (*)(const char* szPAN);

/**
 * @brief Low-level APDU transmit callback for PC/SC token communication.
 *
 * Sends an APDU command to the card and receives the response.
 * Used as a transport callback by the IAS authentication layer.
 */
HRESULT TokenTransmitCallback(void* data, uint8_t* apdu, DWORD apduSize,
                              uint8_t* resp, DWORD* respSize);
