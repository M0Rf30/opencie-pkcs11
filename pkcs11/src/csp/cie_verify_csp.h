// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file cie_verify_csp.h
 * @brief CIE signature verification function-pointer types.
 *
 * Declares the external-facing API for verifying signed documents
 * (CAdES/PAdES/XAdES), querying signature count and per-signature info, and
 * extracting the original content from a .p7m envelope.
 */

#pragma once

#include <cstdio>

#include "cie_enable.h"
#include "sign/cie_verify.h"

/** @brief Verify all signatures in the given file and return the overall
 * result. */
using cie_verify_fn = CK_RV (*)(const char* inFilePath);

/** @brief Return the number of signatures found in the last verified document.
 */
using cie_get_sign_count_fn = CK_RV (*)();

/** @brief Retrieve verification details for the signature at @p index. */
using cie_get_verify_info_fn = CK_RV (*)(int index,
                                         struct verifyInfo_t* vInfos);

/** @brief Extract the original content from a CAdES .p7m envelope. */
using cie_extract_p7m_fn = CK_RV (*)(const char* inFilePath,
                                     const char* outFilePath);
