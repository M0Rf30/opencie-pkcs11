// SPDX-License-Identifier: LGPL-3.0-or-later
/*
 * scard_types.h — Platform-independent smart card type definitions.
 *
 * On desktop (Linux/macOS/Windows): includes the platform's native
 * PC/SC headers (winscard.h, wintypes.h, PCSC.framework).
 *
 * On Android: provides the same type names and constants so that
 * code using ISmartCardTransport compiles without winscard.h.
 */
#pragma once

#if defined(__ANDROID__)

#include <cstdint>

/* ---------- Basic Windows-compat types (subset of wintypes.h) ---------- */
typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned long DWORD;
typedef long LONG;
typedef int16_t BOOL;

typedef BYTE *LPBYTE;
typedef const BYTE *LPCBYTE;
typedef DWORD *LPDWORD;
typedef char *LPSTR;
typedef const char *LPCSTR;
typedef void *LPVOID;
typedef const void *LPCVOID;

#ifndef HRESULT
typedef long HRESULT;
#endif

/* ---------- Smart card handle types ---------- */
typedef uintptr_t SCARDCONTEXT;
typedef uintptr_t SCARDHANDLE;
typedef SCARDCONTEXT *LPSCARDCONTEXT;
typedef SCARDHANDLE *LPSCARDHANDLE;

/* ---------- SCARD_IO_REQUEST ---------- */
struct SCARD_IO_REQUEST {
  unsigned long dwProtocol;
  unsigned long cbPciLength;
};

/* Dummy PCI structure for T=1 protocol (Android NFC is always T=1-like) */
static const SCARD_IO_REQUEST g_SCARD_PCI_T1 = {2, sizeof(SCARD_IO_REQUEST)};
#define SCARD_PCI_T1 (&g_SCARD_PCI_T1)

/* ---------- SCARD_READERSTATE ---------- */
struct SCARD_READERSTATE {
  const char *szReader;
  void *pvUserData;
  DWORD dwCurrentState;
  DWORD dwEventState;
  DWORD cbAtr;
  unsigned char rgbAtr[36];
};

/* ---------- Error codes (match PC/SC Lite values) ---------- */
#define SCARD_S_SUCCESS 0x00000000L
#define SCARD_E_CANCELLED 0x80100002L
#define SCARD_E_INVALID_HANDLE 0x80100003L
#define SCARD_E_INVALID_PARAMETER 0x80100004L
#define SCARD_E_INSUFFICIENT_BUFFER 0x80100008L
#define SCARD_E_TIMEOUT 0x8010000AL
#define SCARD_E_SYSTEM_CANCELLED 0x80100012L
#define SCARD_E_NOT_TRANSACTED 0x80100016L
#define SCARD_E_NO_SERVICE 0x8010001DL
#define SCARD_E_SERVICE_STOPPED 0x8010001EL
#define SCARD_E_NO_READERS_AVAILABLE 0x8010002EL
#define SCARD_W_UNPOWERED_CARD 0x80100067L
#define SCARD_W_RESET_CARD 0x80100068L
#define SCARD_W_REMOVED_CARD 0x80100069L
#define SCARD_W_WRONG_CHV 0x8010006BL
#define SCARD_W_CHV_BLOCKED 0x8010006CL

/* ---------- Scope ---------- */
#define SCARD_SCOPE_USER 0x0000
#define SCARD_SCOPE_SYSTEM 0x0002

/* ---------- Share modes ---------- */
#define SCARD_SHARE_EXCLUSIVE 0x0001
#define SCARD_SHARE_SHARED 0x0002

/* ---------- Protocols ---------- */
#define SCARD_PROTOCOL_T0 0x0001
#define SCARD_PROTOCOL_T1 0x0002

/* ---------- Card dispositions ---------- */
#define SCARD_LEAVE_CARD 0x0000
#define SCARD_RESET_CARD 0x0001
#define SCARD_UNPOWER_CARD 0x0002

/* ---------- Reader states ---------- */
#define SCARD_STATE_CHANGED 0x0002
#define SCARD_STATE_UNAVAILABLE 0x0008
#define SCARD_STATE_EMPTY 0x0010
#define SCARD_STATE_PRESENT 0x0020

/* ---------- Attributes ---------- */
#ifndef SCARD_ATTR_VALUE
#define SCARD_ATTR_VALUE(Class, Tag) \
  ((((uint32_t)(Class)) << 16) | ((uint32_t)(Tag)))
#endif
#ifndef SCARD_CLASS_ICC_STATE
#define SCARD_CLASS_ICC_STATE 9
#endif
#ifndef SCARD_ATTR_ATR_STRING
#define SCARD_ATTR_ATR_STRING SCARD_ATTR_VALUE(SCARD_CLASS_ICC_STATE, 0x0303)
#endif

/* ---------- Misc ---------- */
#ifndef INFINITE
#define INFINITE 0xFFFFFFFF
#endif

#elif defined(_WIN32)
// clang-format off
#include <winsock2.h>
#include <winscard.h>
// clang-format on
#else
/* Linux / macOS — use platform PC/SC headers */
#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>
#endif

/* ---------- Composite protocol mask (all platforms) ---------- */
#ifndef SCARD_PROTOCOL_Tx
#define SCARD_PROTOCOL_Tx (SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1)
#endif
