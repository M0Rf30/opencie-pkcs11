// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

/**
 * @file cie_sign_csp.h
 * @brief CIE digital signature function-pointer type and completion callback.
 *
 * Declares the cie_sign_fn signature used by the PKCS#11 module to expose
 * CAdES / PAdES / XAdES signing via the CIE card, with optional visible
 * PDF signature placement parameters (page, position, image).
 */

#pragma once

#include "csp/cie_enable.h"
#include "pkcs11/cryptoki.h"

/** @brief Callback invoked when a signing operation completes. */
typedef CK_CALLBACK_FUNCTION(CK_RV, SIGN_COMPLETED_CALLBACK)(const int ret);

/**
 * @brief Sign a document using the CIE card.
 *
 * @param inFilePath    Path to the input document.
 * @param type          Signature type: "p7m" (CAdES), "pdf" (PAdES), or "xml"
 * (XAdES).
 * @param pin           User PIN for CIE authentication.
 * @param pan           Card PAN (Personal Access Number).
 * @param page          PDF page for visible signature (PAdES only, 0-based).
 * @param x,y,w,h       Visible signature rectangle coordinates (PAdES only).
 * @param imageData     PNG image bytes for signature overlay (PAdES only, may
 * be null).
 * @param imageDataLen  Length of imageData in bytes; 0 if imageData is null.
 * @param outFilePath   Path where the signed document will be written.
 */
using cie_sign_fn = CK_RV (*)(const char* inFilePath, const char* type,
                              const char* pin, const char* pan, int page,
                              float x, float y, float w, float h,
                              const unsigned char* imageData, int imageDataLen,
                              const char* outFilePath,
                              PROGRESS_CALLBACK progressCallBack,
                              SIGN_COMPLETED_CALLBACK completedCallBack);
