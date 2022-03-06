#pragma once

#include "pcsc/smart_card_transport.h"

class CCardContext {
 public:
  ISmartCardTransport &transport;
  SCARDCONTEXT hContext;

  CCardContext(ISmartCardTransport &transport);
  ~CCardContext(void);

  operator SCARDCONTEXT();
  void validate();
  void renew();

 private:
  void getContext();
};
