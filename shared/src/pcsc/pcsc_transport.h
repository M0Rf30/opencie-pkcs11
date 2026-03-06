/*
 * PCSCTransport.h — PC/SC backend for ISmartCardTransport.
 *
 * Thin delegation layer: every method calls the corresponding
 * SCard* function from the platform's PC/SC library (pcsclite on
 * Linux, PCSC.framework on macOS, winscard.dll on Windows).
 *
 * Header-only — no .cpp needed.
 */
#pragma once

#include "smart_card_transport.h"

#if !defined(__ANDROID__)

class PCSCTransport final : public ISmartCardTransport {
 public:
  /* ---- Context lifecycle ---- */

  LONG EstablishContext(DWORD dwScope, LPSCARDCONTEXT phContext) override {
    return SCardEstablishContext(dwScope, nullptr, nullptr, phContext);
  }

  LONG ReleaseContext(SCARDCONTEXT hContext) override {
    return SCardReleaseContext(hContext);
  }

  LONG IsValidContext(SCARDCONTEXT hContext) override {
    return SCardIsValidContext(hContext);
  }

  /* ---- Reader enumeration ---- */

  LONG ListReaders(SCARDCONTEXT hContext, LPSTR mszReaders,
                   LPDWORD pcchReaders) override {
    return SCardListReaders(hContext, nullptr, mszReaders, pcchReaders);
  }

  LONG GetStatusChange(SCARDCONTEXT hContext, DWORD dwTimeout,
                       SCARD_READERSTATE *rgReaderStates,
                       DWORD cReaders) override {
    return SCardGetStatusChange(hContext, dwTimeout, rgReaderStates, cReaders);
  }

  LONG Cancel(SCARDCONTEXT hContext) override { return SCardCancel(hContext); }

  /* ---- Card connection ---- */

  LONG Connect(SCARDCONTEXT hContext, LPCSTR szReader, DWORD dwShareMode,
               DWORD dwPreferredProtocols, LPSCARDHANDLE phCard,
               LPDWORD pdwActiveProtocol) override {
    return SCardConnect(hContext, szReader, dwShareMode, dwPreferredProtocols,
                        phCard, pdwActiveProtocol);
  }

  LONG Disconnect(SCARDHANDLE hCard, DWORD dwDisposition) override {
    return SCardDisconnect(hCard, dwDisposition);
  }

  LONG Reconnect(SCARDHANDLE hCard, DWORD dwShareMode,
                 DWORD dwPreferredProtocols, DWORD dwInitialization,
                 LPDWORD pdwActiveProtocol) override {
    return SCardReconnect(hCard, dwShareMode, dwPreferredProtocols,
                          dwInitialization, pdwActiveProtocol);
  }

  /* ---- APDU transport ---- */

  LONG Transmit(SCARDHANDLE hCard, const SCARD_IO_REQUEST *pioSendPci,
                LPCBYTE pbSendBuffer, DWORD cbSendLength, LPBYTE pbRecvBuffer,
                LPDWORD pcbRecvLength) override {
    return SCardTransmit(hCard, pioSendPci, pbSendBuffer, cbSendLength, nullptr,
                         pbRecvBuffer, pcbRecvLength);
  }

  /* ---- Transaction locking ---- */

  LONG BeginTransaction(SCARDHANDLE hCard) override {
    return SCardBeginTransaction(hCard);
  }

  LONG EndTransaction(SCARDHANDLE hCard, DWORD dwDisposition) override {
    return SCardEndTransaction(hCard, dwDisposition);
  }

  /* ---- Card attributes ---- */

  LONG GetAttrib(SCARDHANDLE hCard, DWORD dwAttrId, LPBYTE pbAttr,
                 LPDWORD pcbAttrLen) override {
    return SCardGetAttrib(hCard, dwAttrId, pbAttr, pcbAttrLen);
  }
};

#endif /* !__ANDROID__ */
