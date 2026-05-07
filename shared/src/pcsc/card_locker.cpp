// SPDX-License-Identifier: LGPL-3.0-or-later
#include "card_locker.h"

extern CLog Log;

CCardLocker::CCardLocker(ISmartCardTransport &transport, SCARDHANDLE card)
    : transport(transport), hCard(card) {
  Lock();
}

CCardLocker::~CCardLocker(void) { Unlock(); }

void CCardLocker::Lock() {
  init_func

      transport.BeginTransaction(hCard);
}

void CCardLocker::Unlock() {
  init_func

      transport.EndTransaction(hCard, SCARD_LEAVE_CARD);
}
