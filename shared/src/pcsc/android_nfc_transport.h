// SPDX-License-Identifier: LGPL-3.0-or-later
/*
 * AndroidNFCTransport.h — Android NFC (IsoDep) backend for ISmartCardTransport.
 *
 * Bridges the ISmartCardTransport interface to Android's NFC stack via JNI.
 * The Android app passes an IsoDep object before calling C_Initialize():
 *
 *   1. System.loadLibrary("cie-pkcs11")   →  JNI_OnLoad stores JavaVM*
 *   2. cie_set_nfc_tag(env, isoDepObject)   →  stores IsoDep global ref
 *   3. C_Initialize(NULL)                  →  creates AndroidNFCTransport
 *   4. ... normal PKCS#11 usage ...
 *   5. C_Finalize(NULL)
 *   6. cie_clear_nfc_tag(env)               →  releases IsoDep global ref
 */
#pragma once

#if defined(__ANDROID__)

#include <jni.h>

#include <mutex>
#include <vector>

#include "pcsc/smart_card_transport.h"

/* --- JNI bridge (called by Android app) --- */
extern "C" {
/* Store the IsoDep object for the current NFC session.
 * Must be called before C_Initialize(). */
void cie_set_nfc_tag(JNIEnv *env, jobject isoDep);

/* Clear the IsoDep reference (call when NFC tag is lost). */
void cie_clear_nfc_tag(JNIEnv *env);
}

class AndroidNFCTransport final : public ISmartCardTransport {
 public:
  AndroidNFCTransport();
  ~AndroidNFCTransport() override;

  /* ---- Context lifecycle (no-ops on Android) ---- */

  LONG EstablishContext(DWORD dwScope, LPSCARDCONTEXT phContext) override;
  LONG ReleaseContext(SCARDCONTEXT hContext) override;
  LONG IsValidContext(SCARDCONTEXT hContext) override;

  /* ---- Reader enumeration ---- */

  LONG ListReaders(SCARDCONTEXT hContext, LPSTR mszReaders,
                   LPDWORD pcchReaders) override;
  LONG GetStatusChange(SCARDCONTEXT hContext, DWORD dwTimeout,
                       SCARD_READERSTATE *rgReaderStates,
                       DWORD cReaders) override;
  LONG Cancel(SCARDCONTEXT hContext) override;

  /* ---- Card connection ---- */

  LONG Connect(SCARDCONTEXT hContext, LPCSTR szReader, DWORD dwShareMode,
               DWORD dwPreferredProtocols, LPSCARDHANDLE phCard,
               LPDWORD pdwActiveProtocol) override;
  LONG Disconnect(SCARDHANDLE hCard, DWORD dwDisposition) override;
  LONG Reconnect(SCARDHANDLE hCard, DWORD dwShareMode,
                 DWORD dwPreferredProtocols, DWORD dwInitialization,
                 LPDWORD pdwActiveProtocol) override;

  /* ---- APDU transport ---- */

  LONG Transmit(SCARDHANDLE hCard, const SCARD_IO_REQUEST *pioSendPci,
                LPCBYTE pbSendBuffer, DWORD cbSendLength, LPBYTE pbRecvBuffer,
                LPDWORD pcbRecvLength) override;

  /* ---- Transaction locking (no-ops on Android) ---- */

  LONG BeginTransaction(SCARDHANDLE hCard) override;
  LONG EndTransaction(SCARDHANDLE hCard, DWORD dwDisposition) override;

  /* ---- Card attributes ---- */

  LONG GetAttrib(SCARDHANDLE hCard, DWORD dwAttrId, LPBYTE pbAttr,
                 LPDWORD pcbAttrLen) override;

 private:
  jobject isoDep_;     /* Global ref to android.nfc.tech.IsoDep */
  jclass isoDepClass_; /* Global ref to cached class */

  /* Cached JNI method IDs */
  jmethodID connectId_;
  jmethodID closeId_;
  jmethodID transceiveId_;
  jmethodID isConnectedId_;
  jmethodID getHistBytesId_;
  jmethodID getHiLayerRespId_;

  std::vector<uint8_t> cachedATR_;
  bool connected_ = false;
  std::mutex mutex_;

  /* Synthetic handle/context values (Android has only one NFC reader) */
  static constexpr SCARDCONTEXT kDummyContext = 0x4E464300; /* "NFC\0" */
  static constexpr SCARDHANDLE kDummyHandle = 0x4E464301;   /* "NFC\1" */

  JNIEnv *getEnv();
  void buildATR(JNIEnv *env);
  void cacheMethodIDs(JNIEnv *env);
};

#endif /* __ANDROID__ */
