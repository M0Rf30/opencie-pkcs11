/*
 * ISmartCardTransport.h — Abstract smart card transport interface.
 *
 * All smart card operations (context management, reader enumeration,
 * card connection, APDU transport, transactions) go through this
 * interface.  Platform backends implement it:
 *
 *   PCSCTransport        — Linux / macOS / Windows (wraps winscard.h)
 *   android_nfc_transport  — Android (JNI bridge to IsoDep)
 */
#pragma once

#include <memory>

#include "scard_types.h"

class ISmartCardTransport {
 public:
  virtual ~ISmartCardTransport() = default;

  /* ---- Context lifecycle ---- */

  virtual LONG EstablishContext(DWORD dwScope, LPSCARDCONTEXT phContext) = 0;

  virtual LONG ReleaseContext(SCARDCONTEXT hContext) = 0;

  virtual LONG IsValidContext(SCARDCONTEXT hContext) = 0;

  /* ---- Reader enumeration ---- */

  virtual LONG ListReaders(SCARDCONTEXT hContext, LPSTR mszReaders,
                           LPDWORD pcchReaders) = 0;

  virtual LONG GetStatusChange(SCARDCONTEXT hContext, DWORD dwTimeout,
                               SCARD_READERSTATE *rgReaderStates,
                               DWORD cReaders) = 0;

  virtual LONG Cancel(SCARDCONTEXT hContext) = 0;

  /* ---- Card connection ---- */

  virtual LONG Connect(SCARDCONTEXT hContext, LPCSTR szReader,
                       DWORD dwShareMode, DWORD dwPreferredProtocols,
                       LPSCARDHANDLE phCard, LPDWORD pdwActiveProtocol) = 0;

  virtual LONG Disconnect(SCARDHANDLE hCard, DWORD dwDisposition) = 0;

  virtual LONG Reconnect(SCARDHANDLE hCard, DWORD dwShareMode,
                         DWORD dwPreferredProtocols, DWORD dwInitialization,
                         LPDWORD pdwActiveProtocol) = 0;

  /* ---- APDU transport ---- */

  virtual LONG Transmit(SCARDHANDLE hCard, const SCARD_IO_REQUEST *pioSendPci,
                        LPCBYTE pbSendBuffer, DWORD cbSendLength,
                        LPBYTE pbRecvBuffer, LPDWORD pcbRecvLength) = 0;

  /* ---- Transaction locking ---- */

  virtual LONG BeginTransaction(SCARDHANDLE hCard) = 0;

  virtual LONG EndTransaction(SCARDHANDLE hCard, DWORD dwDisposition) = 0;

  /* ---- Card attributes ---- */

  virtual LONG GetAttrib(SCARDHANDLE hCard, DWORD dwAttrId, LPBYTE pbAttr,
                         LPDWORD pcbAttrLen) = 0;
};

using SmartCardTransportPtr = std::shared_ptr<ISmartCardTransport>;
