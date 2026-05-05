// SPDX-License-Identifier: LGPL-3.0-or-later
#include "pcsc.h"

#ifndef _WIN32
#include <unistd.h>
#endif

#include <thread>

#include "util/util_exception.h"

struct transData {
  SCARDCONTEXT context;
};
bool safeTransaction::isLocked() { return locked; }
safeTransaction::safeTransaction(ISmartCardTransport &transport,
                                 const safeConnection &conn,
                                 DWORD dwDisposition)
    : transport(transport) {
  this->hCard = conn.hCard;
  this->dwDisposition = dwDisposition;
  locked = false;

#ifdef _WIN32
  auto td = std::make_shared<struct transData>();
  td->context = conn.hContext;
  auto thread = std::thread([td, &transport]() {
    for (int i = 0; i < 10; i++) {
      Sleep(500);
    }
    transport.Cancel(td->context);
    return 0;
  });
  thread.detach();
#endif

  if (transport.BeginTransaction(hCard) != SCARD_S_SUCCESS) {
    this->hCard = 0;
    this->dwDisposition = 0;
    return;
  } else {
    locked = true;
  }
}

void safeTransaction::unlock() {
  if (hCard != 0 && locked) {
    transport.EndTransaction(hCard, dwDisposition);
    locked = false;
  }
}

safeTransaction::~safeTransaction() {
  if (hCard != 0 && locked) {
    transport.EndTransaction(hCard, dwDisposition);
  }
}

safeConnection::safeConnection(ISmartCardTransport &transport,
                               SCARDHANDLE hCard)
    : transport(transport) {
  this->hCard = hCard;
}

safeConnection::safeConnection(ISmartCardTransport &transport,
                               SCARDCONTEXT hContext, LPCSTR szReader,
                               DWORD dwShareMode)
    : transport(transport) {
  DWORD dwProtocol;
  this->hContext = hContext;
  if (transport.Connect(hContext, szReader, dwShareMode, SCARD_PROTOCOL_T1,
                        &hCard, &dwProtocol) != SCARD_S_SUCCESS)
    hCard = 0;
}

safeConnection::~safeConnection() {
  if (hCard) {
    transport.Disconnect(hCard, SCARD_RESET_CARD);
  }
}
safeConnection::operator SCARDHANDLE() { return hCard; }

readerMonitor::~readerMonitor() {
  stopMonitor = true;
  transport.Cancel(hContext);
  Thread.join();
  transport.ReleaseContext(hContext);
}

readerMonitor::readerMonitor(ISmartCardTransport &transport,
                             void (*eventHandler)(std::string &reader,
                                                  bool insert, void *appData),
                             void *appData)
    : transport(transport), appData(appData) {
  LONG _call_ris;
  if ((_call_ris = transport.EstablishContext(SCARD_SCOPE_SYSTEM, &hContext)) !=
      0) {
    throw windows_error(_call_ris);
  }
  stopMonitor = false;
  readerEvent = eventHandler;

  Thread = std::thread(
      [](readerMonitor *rm) -> DWORD {
        std::vector<std::string> readerList;
        std::vector<SCARD_READERSTATE> states;

        auto loadReaderList = [&]() -> void {
          char *readers = nullptr;
          DWORD len = 0;

          if (rm->transport.ListReaders(rm->hContext, nullptr, &len))
            throw logged_error("Nessun lettore installato");

          readers = static_cast<char *>(calloc(len, sizeof(char)));
          rm->transport.ListReaders(rm->hContext, readers, &len);

          const char *curReader = readers;
          readerList.clear();
          for (; curReader[0] != 0; curReader += strnlen(curReader, len) + 1)
            readerList.push_back(std::string(curReader));

          free(readers);

          states.resize(static_cast<DWORD>(readerList.size()) + 1);
          for (DWORD i = 0; i < readerList.size(); i++) {
            states[i].szReader = readerList[i].c_str();
          }
          auto &PnP = states[static_cast<DWORD>(readerList.size())];
          PnP.szReader = "\\\\?PnP?\\Notification";
          PnP.pvUserData =
              const_cast<void *>(reinterpret_cast<const void *>(PnP.szReader));

          rm->transport.GetStatusChange(rm->hContext, 0, states.data(),
                                        states.size());
          for (DWORD i = 0; i < states.size(); i++)
            states[i].dwCurrentState = states[i].dwEventState;
        };
        loadReaderList();

        while (!rm->stopMonitor) {
          if (rm->transport.GetStatusChange(rm->hContext, INFINITE,
                                            states.data(),
                                            states.size()) == SCARD_E_CANCELLED)
            break;
          for (DWORD i = 0; i < states.size(); i++) {
            auto &state = states[i];
            if (state.pvUserData != nullptr &&
                (state.dwEventState & SCARD_STATE_CHANGED) ==
                    SCARD_STATE_CHANGED) {
              loadReaderList();
              break;
            }
            if (((state.dwCurrentState & SCARD_STATE_PRESENT) ==
                 SCARD_STATE_PRESENT) &&
                ((state.dwEventState & SCARD_STATE_PRESENT) == 0))
              rm->readerEvent(readerList[i], false, rm->appData);

            else if (((state.dwCurrentState & SCARD_STATE_PRESENT) == 0) &&
                     ((state.dwEventState & SCARD_STATE_PRESENT) ==
                      SCARD_STATE_PRESENT))
              rm->readerEvent(readerList[i], true, rm->appData);

            state.dwCurrentState = state.dwEventState;
          }
        }
        return 0;
      },
      this);
}
