// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

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
