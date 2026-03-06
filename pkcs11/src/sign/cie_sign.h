// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

/**
 * @file cie_sign.h
 * @brief High-level CIE document signing using an authenticated IAS session.
 *
 * CIESign wraps the IAS (Identification, Authentication, Signature) smart card
 * interface to perform CAdES (.p7m), PAdES (PDF), or XAdES (XML) digital
 * signatures.  The IAS session must already be authenticated before calling
 * sign().
 */

#pragma once

#include "csp/ias.h"
#include "sign/cie_sign_api.h"

/**
 * @brief Performs document signing using a CIE card's private key.
 *
 * Requires an already-authenticated IAS session.  Supports visible PDF
 * signatures with optional image overlay placement.
 */
class CIESign {
 private:
  IAS* ias;  ///< Authenticated IAS session for card communication.

 public:
  CIESign(IAS* ias);
  ~CIESign();

  /**
   * @brief Sign a document file.
   *
   * @param inFilePath      Path to the document to sign.
   * @param type            Signature type: "p7m", "pdf", or "xml".
   * @param pin             User PIN (for re-authentication if needed).
   * @param page            PDF page for visible signature (0-based, PAdES
   * only).
   * @param x,y,w,h         Signature rectangle on the page (PAdES only).
   * @param imagePathFile   Optional image overlay path (PAdES only).
   * @param outFilePath     Output path for the signed document.
   * @return 0 on success, non-zero error code on failure.
   */
  uint16_t sign(const char* inFilePath, const char* type, const char* pin,
                int page, float x, float y, float w, float h,
                const char* imagePathFile, const char* outFilePath);
};
