// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <podofo/podofo.h>
#include "sign/disigonsdk.h"
#include <memory>
#include "Util/byte_array.h"

struct SignatureAppearanceInfo {
  int left;
  int bottom;
  int width;
  int heigth;
};

class PDFVerifier {
 public:
  PDFVerifier();

  virtual ~PDFVerifier();

  int Load(const char* pdf, int len);
  int Load(const char* szFilePath);

  int GetNumberOfSignatures();

  int VerifySignature(size_t index, const char* szDate, char* signatureType,
                      REVOCATION_INFO* pRevocationInfo);

  int GetSignature(size_t index, UUCByteArray& signedDocument,
                   SignatureAppearanceInfo& appearanceInfo);

  static int GetNumberOfSignatures(PoDoFo::PdfMemDocument* pPdfDocument);
  static int GetNumberOfSignatures(const char* szFilePath);

 private:
  UUCByteArray m_data;
  static bool IsSignatureField(const PoDoFo::PdfMemDocument* pDoc,
                               const PoDoFo::PdfObject* const pObj);

  int VerifySignature(const PoDoFo::PdfMemDocument* pDoc, const PoDoFo::PdfObject* const pObj,
                      const char* szDate, char* signatureType,
                      REVOCATION_INFO* pRevocationInfo);

  int GetSignature(const PoDoFo::PdfMemDocument* pDoc, const PoDoFo::PdfObject* const pObj,
                   UUCByteArray& signedDocument,
                   SignatureAppearanceInfo& appearanceInfo);

  std::unique_ptr<PoDoFo::PdfMemDocument> m_pPdfMemDocument;

  int m_actualLen;

  char* m_szDocBuffer;
};

