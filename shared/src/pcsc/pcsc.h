#pragma once

#include <string>
#include <thread>
#include <vector>

#include "pcsc/smart_card_transport.h"
#include "Util/array.h"

class safeConnection {
 public:
  ISmartCardTransport &transport;
  SCARDCONTEXT hContext;
  SCARDHANDLE hCard;
  safeConnection(ISmartCardTransport &transport, SCARDCONTEXT hContext,
                 LPCSTR szReader, DWORD dwShareMode);
  safeConnection(ISmartCardTransport &transport, SCARDHANDLE hCard);
  ~safeConnection();
  operator SCARDHANDLE();
};

class safeTransaction {
  ISmartCardTransport &transport;
  SCARDHANDLE hCard;
  bool locked;
  DWORD dwDisposition;

 public:
  safeTransaction(ISmartCardTransport &transport, safeConnection &conn,
                  DWORD dwDisposition);
  void unlock();
  bool isLocked();
  ~safeTransaction();
};

class readerMonitor {
  ISmartCardTransport &transport;
  SCARDCONTEXT hContext;
  std::thread Thread;
  void *appData;
  void (*readerEvent)(std::string &reader, bool insert, void *appData);
  bool stopMonitor;

 public:
  readerMonitor(ISmartCardTransport &transport,
                void (*readerEvent)(std::string &reader, bool insert,
                                    void *appData),
                void *appData);
  ~readerMonitor();
};
