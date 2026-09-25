// SPDX-License-Identifier: LGPL-3.0-or-later
/*
 * linux_nfc_transport.h — Linux kernel NFC backend for ISmartCardTransport.
 *
 * Talks to the in-kernel NFC subsystem (the stack phone NFC controllers use)
 * instead of PC/SC:
 *
 *   control  : generic netlink family "nfc" (device up, poll, target info)
 *   data     : AF_NFC / NFC_SOCKPROTO_RAW socket connected to the target,
 *              carrying ISO-DEP (ISO 14443-4) APDUs
 *
 * This is the backend Linux-mobile devices (postmarketOS and friends) need,
 * because neard exposes NDEF operations only and cannot carry the CIE's
 * application-specific APDUs.
 *
 * Opt-in: createSmartCardTransport() selects it only when the environment
 * variable OPENCIE_NFC_BACKEND is set to "kernel". PC/SC stays the default
 * on desktop Linux.
 */
#pragma once

#if defined(__linux__) && !defined(__ANDROID__)

#include <atomic>
#include <cstdint>
#include <mutex>
#include <vector>

#include "smart_card_transport.h"

/**
 * Synthesizes the ATR a contactless ISO 14443-4 target would have had, from
 * its Answer To Select. Contactless cards carry no ATR, but the PKCS#11 slot
 * layer matches CIE chip templates on one, so it is derived from the ATS
 * historical bytes exactly like the Android backend derives it from
 * IsoDep.getHistoricalBytes().
 *
 * @param ats  raw ATS bytes (TL, T0, [TA/TB/TC], historical bytes); may be
 *             empty or absent for type B targets.
 * @param len  number of ATS bytes.
 * @return the synthetic ATR, never empty (a minimal ATR is returned when no
 *         historical bytes are available).
 */
std::vector<uint8_t> linuxNfcAtrFromAts(const uint8_t *ats, size_t len);

class LinuxNFCTransport final : public ISmartCardTransport {
 public:
  LinuxNFCTransport();
  ~LinuxNFCTransport() override;

  /* ---- Context lifecycle ---- */

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

  /* ---- Transaction locking (single owner: no-ops) ---- */

  LONG BeginTransaction(SCARDHANDLE hCard) override;
  LONG EndTransaction(SCARDHANDLE hCard, DWORD dwDisposition) override;

  /* ---- Card attributes ---- */

  LONG GetAttrib(SCARDHANDLE hCard, DWORD dwAttrId, LPBYTE pbAttr,
                 LPDWORD pcbAttrLen) override;

 private:
  /** One ISO-DEP target activated by the kernel poll loop. */
  struct Target {
    uint32_t deviceIndex = 0;
    uint32_t targetIndex = 0;
    /** NFC_PROTO_ISO14443 (type A) or NFC_PROTO_ISO14443_B (type B). */
    uint32_t protocol = 0;
    /** Raw Answer To Select (type A); empty for type B targets. */
    std::vector<uint8_t> ats;
  };

  bool ensureNetlink();
  bool findDevice(uint32_t *deviceIndex);
  /** Consumes the ACK for request @p seq; returns 0 or a negative errno. */
  int awaitAck(uint32_t seq);
  bool powerUpAndPoll(uint32_t deviceIndex);
  bool waitForTarget(uint32_t deviceIndex, DWORD timeoutMs, Target *target);
  bool openDataSocket(const Target &target);
  void closeDataSocket();
  void buildATR(const Target &target);

  int netlinkFd_ = -1; /* generic netlink control socket */
  int dataFd_ = -1;    /* AF_NFC raw data socket */
  uint16_t familyId_ = 0;
  uint32_t eventGroup_ = 0;
  uint32_t sequence_ = 0;

  bool polling_ = false;
  bool hasTarget_ = false;
  /* Cancel() is called from the transaction watchdog thread while another
   * thread blocks in GetStatusChange(), so this cannot be a plain bool. */
  std::atomic<bool> cancelled_ {false};
  Target target_;
  std::vector<uint8_t> cachedATR_;
  std::mutex mutex_;

  static constexpr SCARDCONTEXT kContext = 0x4B4E4643; /* "KNFC" */
  static constexpr SCARDHANDLE kHandle = 0x4B4E4644;   /* "KNFD" */
};

#endif /* __linux__ && !__ANDROID__ */
