#pragma once

#include "pcsc/smart_card_transport.h"
#include "pcsc/token.h"
#include "Util/syncro_mutex.h"

class CCardLocker {
  ISmartCardTransport &transport;
  SCARDHANDLE hCard;

 public:
  CCardLocker(ISmartCardTransport &transport, SCARDHANDLE card);
  ~CCardLocker(void);
  void Lock();
  void Unlock();
};
