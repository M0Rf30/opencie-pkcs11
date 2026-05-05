// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file pkcs11_functions.h
 * @brief PKCS#11 Cryptoki C API entry point declarations and library constants.
 *
 * Defines the exported C functions that implement the PKCS#11 standard
 * interface, along with library version, session limits, and PIN constants.
 */

#pragma once

#include "pcsc/scard_types.h"
#include "pkcs11/cryptoki.h"

#define MAXVAL 0xffffff     ///< Maximum value for PKCS#11 counters.
#define MAXSESSIONS MAXVAL  ///< Maximum number of concurrent sessions.

#ifndef CK_ENTRY
#ifdef _WIN32
#define CK_ENTRY __declspec(dllexport)
#else
#define CK_ENTRY __attribute__((visibility("default")))
#endif
#endif
#define LIBRARY_VERSION_MAJOR 2  ///< PKCS#11 library major version.
#define LIBRARY_VERSION_MINOR 0  ///< PKCS#11 library minor version.

#define PIN_LEN 8  ///< Expected PIN length in bytes (CIE uses 8-digit PIN).
#define USER_PIN_ID 0x10  ///< On-card file identifier for the user PIN.

#include "logger/logger.h"
extern "C" {
/** @brief Refresh the slot list by re-enumerating attached smart card readers.
 */
CK_RV CK_ENTRY C_UpdateSlotList();
}
