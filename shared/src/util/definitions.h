// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

/**
 * @file definitions.h
 * @brief Platform abstractions, OID constants, and common error codes.
 *
 * Provides Windows/POSIX portability typedefs, cryptographic algorithm
 * identifiers, ASN.1 OID string constants used in CIE digital signatures,
 * PKCS#12, and X.509 certificate processing.
 */

#pragma once

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN
#define STRICMP _stricmp
#else
#define STRICMP strcasecmp
#include "pcsc/scard_types.h"
#endif

#include <cstdint>
#include <cstring>

#include "logging_macros.h"

#define IN
#define OUT

/** @name Cryptographic Algorithm IDs
 *  @{
 */
#define BT0_PADDING 0
#define BT1_PADDING 1
#define BT2_PADDING 2
#ifndef CALG_MD2
#define CALG_MD2 1
#endif
#ifndef CALG_MD5
#define CALG_MD5 2
#endif
#ifndef CALG_SHA1
#define CALG_SHA1 3
#endif
/** @} */

#ifndef ERROR_FILE_NOT_FOUND
#define ERROR_FILE_NOT_FOUND 0x02
#endif
#ifndef ERROR_MORE_DATA
#define ERROR_MORE_DATA 0xE0
#endif
#ifndef ERROR_INVALID_DATA
#define ERROR_INVALID_DATA 0xE1
#endif
#define ERROR_UNABLE_TO_ALLOCATE 0xE2

#define NNULL 0
#define UINT unsigned int

#ifndef _WIN32
#define S_OK 0

#define HANDLE void*
#define PCHAR char*
#define CHAR char
#define VOID void

#ifndef HRESULT
#define HRESULT uint64_t
#endif

/** @name Platform-independent Byte Manipulation
 *  Inline helpers for extracting high/low words and bytes.
 *  @{
 */
#ifndef LOWORD
constexpr uint16_t LOWORD(uint32_t l) {
  return static_cast<uint16_t>(l & 0xFFFF);
}
constexpr uint16_t HIWORD(uint32_t l) {
  return static_cast<uint16_t>((l >> 16) & 0xFFFF);
}
#endif

#ifndef LOBYTE
constexpr uint8_t LOBYTE(uint32_t l) { return static_cast<uint8_t>(l & 0xFF); }
constexpr uint8_t HIBYTE(uint32_t l) {
  return static_cast<uint8_t>((l >> 8) & 0xFF);
}
#endif
/** @} */

#ifndef HRESULT
#define HRESULT unsigned long
#endif
#define HANDLE void*

#ifndef MAX_PATH
#define MAX_PATH 1024
#endif
constexpr uint16_t MAKEWORD(uint8_t lo, uint8_t hi) {
  return static_cast<uint16_t>(lo + (hi * 256));
}

void SetLastError(unsigned long nErr);
unsigned long GetLastError();
#endif  // !_WIN32

/** @name ASN.1 OID Constants
 *  Object Identifier strings for cryptographic algorithms, CMS structures,
 *  X.509 extensions, ETSI qualified certificates, and PKCS#12 bags.
 *  @{
 */
constexpr const char* szIdAASigningCertificateV2OID =
    "1.2.840.113549.1.9.16.2.47";
constexpr const char* szSHA256OID = "2.16.840.1.101.3.4.2.1";
constexpr const char* szSHA512OID = "2.16.840.1.101.3.4.2.3";
constexpr const char* szSHA1OID = "1.3.14.3.2.26";  // "2.16.840.1.101.3.4.1.1"
constexpr const char* szContentTypeOID = "1.2.840.113549.1.9.3";
constexpr const char* szDataOID = "1.2.840.113549.1.7.1";
constexpr const char* szEncDataOID = "1.2.840.113549.1.7.6";
constexpr const char* szMessageDigestOID = "1.2.840.113549.1.9.4";
constexpr const char* szSigningTimeOID = "1.2.840.113549.1.9.5";
constexpr const char* szSha256WithRsaEncryptionOID = "1.2.840.113549.1.1.11";
constexpr const char* szSignedDataOID = "1.2.840.113549.1.7.2";
constexpr const char* szCounterSignatureOID = "1.2.840.113549.1.9.6";
constexpr const char* szCrlDistributionPointsOID = "2.5.29.31";
constexpr const char* szKeyUsageOID = "2.5.29.15";
constexpr const char* szTimestampTokenOID = "1.2.840.113549.1.9.16.2.14";
constexpr const char* szAuthorityInfoAccess = "1.3.6.1.5.5.7.1.1";
constexpr const char* szMethodOCSP = "1.3.6.1.5.5.7.48.1";
constexpr const char* szAuthorityKeyIdentifier = "2.5.29.35";
constexpr const char* szSubjectKeyIdentifier = "2.5.29.14";

constexpr const char* szCertificatePolicies = "2.5.29.32";
constexpr const char* szTimeStampDataOID = "1.2.840.113549.1.9.16.1.31";

constexpr const char* IdEtsiQcsQcCompliance = "0.4.0.1862.1.1";
constexpr const char* IdEtsiQcsLimitValue = "0.4.0.1862.1.2";
constexpr const char* IdEtsiQcsRetentionPeriod = "0.4.0.1862.1.3";
constexpr const char* IdEtsiQcsQcSscd = "0.4.0.1862.1.4";

// PKCS#12 OID
constexpr const char* szKeyBagOID = "1.2.840.113549.1.12.10.1.1";
constexpr const char* szPkcs8ShroudedKeyBagOID = "1.2.840.113549.1.12.10.1.2";
constexpr const char* szCertBagOID = "1.2.840.113549.1.12.10.1.3";
constexpr const char* szCrlBagOID = "1.2.840.113549.1.12.10.1.4";
constexpr const char* szSecretBagOID = "1.2.840.113549.1.12.10.1.5";
constexpr const char* szSafeContentsBagOID = "1.2.840.113549.1.12.10.1.6";
/** @} */

/**
 * @brief Convert a hexadecimal string to an integer.
 * @param szVal Null-terminated hexadecimal string.
 * @return The converted integer value.
 */
int atox(const char* szVal);
#ifndef ERROR_INVALID_HANDLE
#define ERROR_INVALID_HANDLE 6
#endif

#ifndef ERROR_SUCCESS
#define ERROR_SUCCESS 0
#endif
#ifndef _WIN32
#define ODS printf
#else
#include <string>
std::string stdPrintf(const char* format, ...);
#ifndef ODS
#define ODS(...) OutputDebugStringA(stdPrintf(__VA_ARGS__).c_str())
#endif
#endif
/** @brief Function pointer type for crash analytics log callbacks. */
using logFunc = void (*)(const char*);

/** @brief Global crash analytics log callback (may be null). */
extern logFunc pfnCrashliticsLog;

#define BUFFERSIZE 1000

/**
 * @brief Safely delete a heap-allocated pointer and set it to nullptr.
 * @param pointer Pointer to delete.
 */
#define SAFEDELETE(pointer) \
  try {                     \
    if (pointer) {          \
      delete pointer;       \
      pointer = nullptr;    \
    }                       \
  } catch (...) {           \
  }

/** @brief Begin a try block for the __TRY/__CATCH error handling macros. */
#define __TRY try {
/** @brief Catch block that logs unexpected exceptions and returns an error
 * code. */
#define __CATCH                                                                \
  }                                                                            \
  catch (uint64_t err) {                                                       \
    LOG_ERR((0, "__CATCH", "Unexpected Long Exception: %d", err));             \
    ;                                                                          \
    return CIE_SIGN_ERROR_UNEXPECTED;                                          \
  }                                                                            \
  catch (CASN1Exception * pExc) {                                              \
    LOG_ERR((0, "__CATCH", "Unexpected ASN1 Exception: %s", pExc->m_lpszMsg)); \
    return CIE_SIGN_ERROR_UNEXPECTED;                                          \
  }                                                                            \
  catch (...) {                                                                \
    LOG_ERR((0, "__CATCH", "Unexpected Exception"));                           \
    return CIE_SIGN_ERROR_UNEXPECTED;                                          \
  }
