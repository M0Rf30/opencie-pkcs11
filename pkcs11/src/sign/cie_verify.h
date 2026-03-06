// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

/**
 * @file cie_verify.h
 * @brief CIE document signature verification and P7M content extraction.
 *
 * Provides the CIEVerify class for verifying CAdES/PAdES/XAdES signatures
 * and the verifyInfo_t structure that reports per-signer details including
 * certificate validity, revocation status, and signing time.
 */

#pragma once

#include "opencie/cie_ext.h"
#include "sign/cie_sign_api.h"

#define MAX_INFO 20  ///< Maximum number of signers that can be reported.

/**
 * @brief Verifies digital signatures on documents and extracts P7M content.
 *
 * Supports CAdES (.p7m), PAdES (PDF), and XAdES (XML) signed documents.
 * After verification, per-signer details can be queried via verifyInfo_t.
 */
class CIEVerify {
 public:
  CIEVerify();
  ~CIEVerify();

  /**
   * @brief Verify all signatures in a document.
   * @param input_file    Path to the signed document.
   * @param verifyResult  Output structure with overall verification result.
   * @param proxy_address Optional HTTP proxy address (may be null).
   * @param proxy_port    Proxy port (0 = no proxy).
   * @param userPass      Optional proxy credentials ("user:pass", may be null).
   * @return 0 on success, non-zero error code on failure.
   */
  long verify(const char* input_file, VERIFY_RESULT* verifyResult,
              const char* proxy_address, int proxy_port, const char* userPass);

  /**
   * @brief Extract the original content from a CAdES .p7m envelope.
   * @return 0 on success, non-zero error code on failure.
   */
  long get_file_from_p7m(const char* input_file, const char* output_file);
};
