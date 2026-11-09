// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later
#include "pcsc.h"

#ifndef SCARD_E_NO_SMARTCARD
#define SCARD_E_NO_SMARTCARD 0x8010000CL
#endif

#ifndef _WIN32
#include <unistd.h>
#endif

#include <thread>

#include "util/log.h"
#include "util/util_exception.h"

extern CLog Log;

struct transData {
  SCARDCONTEXT context;
  std::atomic<bool> completed {false};
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
  pWatchdogState = td;
  auto thread = std::thread([td, &transport]() {
    for (int i = 0; i < 10 && !td->completed.load(std::memory_order_acquire);
         i++) {
      Sleep(500);
    }
    if (!td->completed.load(std::memory_order_acquire)) {
      transport.Cancel(td->context);
    }
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
#ifdef _WIN32
  if (pWatchdogState)
    pWatchdogState->completed.store(true, std::memory_order_release);
#endif
}

safeTransaction::~safeTransaction() {
  if (hCard != 0 && locked) {
    transport.EndTransaction(hCard, dwDisposition);
  }
#ifdef _WIN32
  if (pWatchdogState)
    pWatchdogState->completed.store(true, std::memory_order_release);
#endif
}

safeConnection::safeConnection(ISmartCardTransport &transport,
                               SCARDHANDLE hCard)
    : transport(transport) {
  this->hCard = hCard;
  this->hContext = 0;
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

FieldCycleResult safeConnection::powerCycleField(
    LPCSTR szReader, std::chrono::milliseconds offWait) {
  if (!transport.SupportsFieldPowerCycle())
    return FieldCycleResult::Unsupported;
  if (!hCard || !hContext || !szReader) return FieldCycleResult::Failed;

  // The old handle is consumed whatever SCardDisconnect says: forget it so
  // the destructor can never disconnect it a second time.
  const SCARDHANDLE old = hCard;
  hCard = 0;
  transport.Disconnect(old, SCARD_UNPOWER_CARD);

  if (offWait.count() > 0) std::this_thread::sleep_for(offWait);

  SCARDHANDLE fresh = 0;
  DWORD protocol = 0;
  const LONG rv = transport.Connect(hContext, szReader, SCARD_SHARE_SHARED,
                                    SCARD_PROTOCOL_Tx, &fresh, &protocol);
  if (rv == static_cast<LONG>(SCARD_W_REMOVED_CARD) ||
      rv == static_cast<LONG>(SCARD_E_NO_SMARTCARD))
    return FieldCycleResult::CardRemoved;
  if (rv != SCARD_S_SUCCESS || !fresh) return FieldCycleResult::Failed;

  hCard = fresh;
  // A failure to open the transaction is not fatal: the existing reset path
  // behaves the same, and APDUs still flow on a shared connection.
  transport.BeginTransaction(hCard);
  return FieldCycleResult::Ok;
}

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

        auto loadReaderList = [&](bool initial = false) -> void {
          DWORD len = 0;
          readerList.clear();
          // Start from zeroed slots: a plain resize() would leave a stale
          // PnP marker (pvUserData) on a slot that is now a reader.
          states.clear();

          LONG lret = rm->transport.ListReaders(rm->hContext, nullptr, &len);
          if (lret != SCARD_S_SUCCESS) {
            if (lret != static_cast<LONG>(SCARD_E_NO_READERS_AVAILABLE))
              throw logged_error("Nessun lettore installato");
          } else if (len >= 2) {
            char *readers = static_cast<char *>(calloc(len, sizeof(char)));
            if (readers == nullptr)
              throw logged_error("Allocazione lettori fallita");
            if (rm->transport.ListReaders(rm->hContext, readers, &len) !=
                SCARD_S_SUCCESS) {
              free(readers);
              throw logged_error("Nessun lettore installato");
            }
            readers[len - 1] = 0;  // never trust the transport's terminator
            const char *curReader = readers;
            const char *const readersEnd = readers + len;
            for (; curReader < readersEnd && curReader[0] != 0;
                 curReader += strlen(curReader) + 1)
              readerList.push_back(std::string(curReader));
            free(readers);
          }

          states.assign(readerList.size() + 1, SCARD_READERSTATE {});
          for (DWORD i = 0; i < readerList.size(); i++) {
            states[i].szReader = readerList[i].c_str();
          }
          auto &PnP = states[static_cast<DWORD>(readerList.size())];
          PnP.szReader = "\\\\?PnP?\\Notification";
          PnP.pvUserData =
              const_cast<void *>(reinterpret_cast<const void *>(PnP.szReader));

          rm->transport.GetStatusChange(rm->hContext, 0, states.data(),
                                        states.size());
          for (DWORD i = 0; i < states.size(); i++) {
            if (initial && i < readerList.size() &&
                (states[i].dwEventState & SCARD_STATE_PRESENT) ==
                    SCARD_STATE_PRESENT)
              rm->readerEvent(readerList[i], true, rm->appData);
            states[i].dwCurrentState = states[i].dwEventState;
          }
        };

        try {
          loadReaderList(true);

          // A bounded wait, not INFINITE: a Cancel() that lands before the
          // transport starts waiting is lost on some backends (pcsc-lite),
          // and the destructor's join() would then hang forever. Re-checking
          // stopMonitor every kPollMs bounds the shutdown latency.
          constexpr DWORD kPollMs = 1000;
          while (!rm->stopMonitor) {
            const LONG rv = rm->transport.GetStatusChange(
                rm->hContext, kPollMs, states.data(), states.size());
            if (rv == static_cast<LONG>(SCARD_E_CANCELLED)) break;
            if (rv == static_cast<LONG>(SCARD_E_TIMEOUT)) continue;
            if (rv != SCARD_S_SUCCESS) {
              // Transient failure (e.g. the PC/SC service restarted): do not
              // spin, back off and rebuild the reader list.
              std::this_thread::sleep_for(std::chrono::milliseconds(500));
              if (!rm->stopMonitor) loadReaderList();
              continue;
            }
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
        } catch (const std::exception &e) {
          Log.writePure("readerMonitor stopped: %s", e.what());
        }
        return 0;
      },
      this);
}
