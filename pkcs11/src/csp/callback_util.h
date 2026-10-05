// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file callback_util.h
 * @brief No-op stand-ins for the optional public API callbacks.
 *
 * The PROGRESS_CALLBACK / COMPLETED_CALLBACK / SIGN_COMPLETED_CALLBACK
 * arguments of the cie_* entry points may be NULL (see opencie/cie_ext.h).
 * Each entry point substitutes the matching no-op at the top of the function
 * so the rest of the body can invoke the callbacks unconditionally.
 */

#pragma once

#include "opencie/cie_ext.h"

namespace opencie {

/** @brief Substitute for a NULL PROGRESS_CALLBACK. */
inline CK_RV noopProgressCallback(int /*progress*/, const char* /*szMessage*/) {
  return CKR_OK;
}

/** @brief Substitute for a NULL COMPLETED_CALLBACK. */
inline CK_RV noopCompletedCallback(const char* /*szPan*/,
                                   const char* /*szName*/,
                                   const char* /*ef_seriale*/) {
  return CKR_OK;
}

/** @brief Substitute for a NULL SIGN_COMPLETED_CALLBACK. */
inline CK_RV noopSignCompletedCallback(int /*ret*/) { return CKR_OK; }

}  // namespace opencie
