// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file card_context.cpp
 * @brief PC/SC context management implementation
 */

#include "pkcs11/card_context.h"

#include "util/util.h"

extern CLog Log;

void CCardContext::getContext() {
  init_func LONG _call_ris;
  if ((_call_ris = transport.EstablishContext(SCARD_SCOPE_USER, &hContext)) !=
      S_OK) {
    // When the Smart Card service (SCardSvr) is not running, treat as a
    // transient condition: leave hContext = 0 and return without throwing so
    // that C_Initialize() can still succeed with an empty slot list.
    if (_call_ris == static_cast<LONG>(SCARD_E_NO_SERVICE) ||
        _call_ris == static_cast<LONG>(SCARD_E_NO_READERS_AVAILABLE)) {
      hContext = 0;
      return;
    }
    throw windows_error(_call_ris);
  }
}

CCardContext::CCardContext(ISmartCardTransport &transport)
    : transport(transport) {
  hContext = 0;
  getContext();
}

CCardContext::~CCardContext(void) {
  if (hContext) transport.ReleaseContext(hContext);
}

CCardContext::operator SCARDCONTEXT() { return hContext; }

void CCardContext::validate() {
  if (hContext)
    if (transport.IsValidContext(hContext) != SCARD_S_SUCCESS) hContext = 0;

  if (hContext == 0) {
    getContext();
  }
}

void CCardContext::renew() {
  init_func

      LONG ris;
  if (hContext)
    if ((ris = transport.ReleaseContext(hContext)) != SCARD_S_SUCCESS)
      throw windows_error(ris);
  hContext = 0;

  getContext();
}
