// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

/**
 * @file pdf_signature_generator.h
 * @brief PDF digital signature field creation and PAdES signing with PoDoFo.
 */

#pragma once

#include <podofo/podofo.h>

#include <memory>
#include <vector>

#include "util/array.h"

/** Maximum size in bytes reserved for the CMS signature within the PDF. */
#define SIGNATURE_SIZE 10000

/**
 * Creates PAdES-compliant signature fields in PDF documents using PoDoFo.
 */
class PdfSignatureGenerator {
 public:
  PdfSignatureGenerator();

  virtual ~PdfSignatureGenerator();

  /** Load a PDF document from a memory buffer. */
  int Load(const char* pdf, int len);

  /**
   * Create an invisible signature field.
   */
  void InitSignature(int pageIndex, const char* szReason,
                     const char* szReasonLabel, const char* szName,
                     const char* szNameLabel, const char* szLocation,
                     const char* szLocationLabel, const char* szFieldName,
                     const char* szSubFilter);

  /**
   * Create a visible signature field at the specified position.
   */
  void InitSignature(int pageIndex, float left, float bottom, float width,
                     float height, const char* szReason,
                     const char* szReasonLabel, const char* szName,
                     const char* szNameLabel, const char* szLocation,
                     const char* szLocationLabel, const char* szFieldName,
                     const char* szSubFilter);

  /**
   * Create a visible signature field at the specified position with an optional
   * image.
   */
  void InitSignature(int pageIndex, float left, float bottom, float width,
                     float height, const char* szReason,
                     const char* szReasonLabel, const char* szName,
                     const char* szNameLabel, const char* szLocation,
                     const char* szLocationLabel, const char* szFieldName,
                     const char* szSubFilter, const char* szImagePath,
                     const char* szDescription);

  /** Serialize the PDF with the embedded signature placeholder. */
  void GetSignedPdf(ByteDynArray& signedPdf);

  /** Return the width of the specified page in points. */
  double getWidth(int pageIndex);

  /** Return the height of the specified page in points. */
  double getHeight(int pageIndex);

  std::unique_ptr<PoDoFo::PdfMemDocument> m_pPdfDocument;
  PoDoFo::PdfSignature* m_pSignatureField;
  std::unique_ptr<PoDoFo::BufferStreamDevice> m_pSignOutputDevice;

 private:
  PoDoFo::charbuff m_pOutputBuffer;
};
