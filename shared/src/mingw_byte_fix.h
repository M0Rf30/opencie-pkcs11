// SPDX-License-Identifier: LGPL-3.0-or-later
// mingw_byte_fix.h
// Fix: std::byte (C++17) vs rpcndr.h "typedef unsigned char byte;" ambiguity
// when "using namespace std;" is in headers (ATR.h, PdfVerifier.h, etc.).
//
// Strategy:
// 1. #define byte to temp name BEFORE any header inclusion.
// 2. Include ALL Windows headers WITHOUT WIN32_LEAN_AND_MEAN so the entire
//    OLE/COM/winscard chain that uses bare "byte" gets processed under
//    the diversion.
// 3. #undef byte — no typedef, no ambiguity. Downstream code that needs
//    byte uses CryptoPP::byte (via "using namespace CryptoPP;") or
//    explicit "unsigned char".
// 4. Re-define WIN32_LEAN_AND_MEAN for downstream code.

#ifdef _WIN32
#ifdef __cplusplus

// Divert byte to temp name before anything uses it.
#define byte _win_byte_temp

// Ensure NOMINMAX is set.
#ifndef NOMINMAX
#define NOMINMAX
#endif

// TEMPORARILY ensure WIN32_LEAN_AND_MEAN is NOT defined, so <windows.h>
// pulls the full header chain (OLE, COM, etc. that use bare "byte").
#ifdef WIN32_LEAN_AND_MEAN
#undef WIN32_LEAN_AND_MEAN
#define _BYTE_FIX_RESTORE_LEAN
#endif

// Pull full Windows headers while byte is diverted.
// winsock2.h MUST come before windows.h to avoid redefinition warnings.
#include <windows.h>
#include <winscard.h>
#include <winsock2.h>
#include <ws2tcpip.h>

// Restore LEAN_AND_MEAN for downstream includes (prevents double-inclusion
// overhead since guards are already set).
#define WIN32_LEAN_AND_MEAN
#ifdef _BYTE_FIX_RESTORE_LEAN
#undef _BYTE_FIX_RESTORE_LEAN
#endif

// Undo diversion. All Windows headers processed.
#undef byte

// Undo Windows macros that conflict with library method names (e.g. PoDoFo).
#ifdef GetObject
#undef GetObject
#endif
#ifdef CreateFont
#undef CreateFont
#endif

#endif  // __cplusplus
#endif  // _WIN32
