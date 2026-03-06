// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

/**
 * @file pdf_verifier.h
 * @brief PDF digital signature verification using PoDoFo.
 */

#pragma once

#include <podofo/podofo.h>

#include <memory>

#include "sign/cie_sign_api.h"
#include "util/array.h"

/** Bounding rectangle of a visible PDF signature annotation. */
struct SignatureAppearanceInfo {
  int left;
  int bottom;
  int width;
  int heigth;
};

/**
 * Loads a PDF document and verifies its digital signatures (PAdES).
 */
class PDFVerifier {
 public:
  PDFVerifier();

  virtual ~PDFVerifier();

  /** Load a PDF from a memory buffer. */
  int Load(const char* pdf, int len);

  /** Load a PDF from a file path. */
  int Load(const char* szFilePath);

  /** Return the number of signature fields in the document. */
  int GetNumberOfSignatures();

  /**
   * Verify the signature at @p index.
   *
   * Fills @p signatureType and @p pRevocationInfo with the result.
   */
  int VerifySignature(size_t index, const char* szDate, char* signatureType,
                      REVOCATION_INFO* pRevocationInfo);

  /**
   * Extract the raw CMS signed data from the signature at @p index.
   */
  int GetSignature(size_t index, ByteDynArray& signedDocument,
                   SignatureAppearanceInfo& appearanceInfo);

  static int GetNumberOfSignatures(PoDoFo::PdfMemDocument* pPdfDocument);
  static int GetNumberOfSignatures(const char* szFilePath);

 private:
  ByteDynArray m_data;
  static bool IsSignatureField(const PoDoFo::PdfMemDocument* pDoc,
                               const PoDoFo::PdfObject* const pObj);

  int VerifySignature(const PoDoFo::PdfMemDocument* pDoc,
                      const PoDoFo::PdfObject* const pObj, const char* szDate,
                      char* signatureType, REVOCATION_INFO* pRevocationInfo);

  int GetSignature(const PoDoFo::PdfMemDocument* pDoc,
                   const PoDoFo::PdfObject* const pObj,
                   ByteDynArray& signedDocument,
                   SignatureAppearanceInfo& appearanceInfo);

  std::unique_ptr<PoDoFo::PdfMemDocument> m_pPdfMemDocument;

  int m_actualLen;

  char* m_szDocBuffer;
};
