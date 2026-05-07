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

#include "csp/ias.h"
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

/**
 * @brief Perform PACE authentication (DH key exchange + PIN/PUK verify).
 *
 * Shared by cie_enable and cie_read_chip.  Selects the IAS/CIE applets,
 * performs the full Diffie-Hellman key exchange, and verifies the PIN or PUK.
 *
 * @param ias                 Initialised IAS instance bound to the card.
 * @param PinId               ROLE_USER (1) or ROLE_ADMIN (2).
 * @param dwFlags             FULL_PIN flag or 0.
 * @param pbPinData           Raw PIN/PUK bytes.
 * @param cbPinData           Length of pbPinData.
 * @param ppbSessionPin       Unused; pass nullptr.
 * @param pcbSessionPin       Unused; pass nullptr.
 * @param progressCallBack    Progress callback (must not be NULL).
 * @param pcAttemptsRemaining Set to remaining attempts on PIN error; may be
 * NULL.
 * @return SCARD_S_SUCCESS on success, SCARD_W_WRONG_CHV / SCARD_W_CHV_BLOCKED
 *         on PIN errors, or another SCARD_* error code.
 */
DWORD CardAuthenticateEx(IAS* ias, DWORD PinId, DWORD dwFlags, BYTE* pbPinData,
                         DWORD cbPinData, BYTE** ppbSessionPin,
                         DWORD* pcbSessionPin,
                         PROGRESS_CALLBACK progressCallBack,
                         int* pcAttemptsRemaining);
