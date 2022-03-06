// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

#include "Util/definitions.h"
#include "pcsc/pcsc.h"
#include "pkcs11/cryptoki.h"

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

// using namespace std

/* CK_NOTIFY is an application callback that processes events */
typedef CK_CALLBACK_FUNCTION(CK_RV, PROGRESS_CALLBACK)(const int progress,
                                                       const char* szMessage);

typedef CK_CALLBACK_FUNCTION(CK_RV, COMPLETED_CALLBACK)(const char* szPan,
                                                        const char* szName,
                                                        const char* ef_seriale);

using cie_enable_fn = CK_RV (*)(const char* szPAN, const char* szPIN,
                              int* attempts, PROGRESS_CALLBACK progressCallBack,
                              COMPLETED_CALLBACK completedCallBack);

using cie_is_enabled_fn = CK_RV (*)(const char* szPAN);
using cie_disable_fn = CK_RV (*)(const char* szPAN);

HRESULT TokenTransmitCallback(void* data, uint8_t* apdu, DWORD apduSize,
                              uint8_t* resp, DWORD* respSize);
