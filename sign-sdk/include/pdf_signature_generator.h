// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <podofo/podofo.h>
#include <memory>
#include <vector>
#include "Util/byte_array.h"

#define SIGNATURE_SIZE 10000


class PdfSignatureGenerator {
 public:
  PdfSignatureGenerator();

  virtual ~PdfSignatureGenerator();

  int Load(const char* pdf, int len);

  void InitSignature(int pageIndex, const char* szReason,
                     const char* szReasonLabel, const char* szName,
                     const char* szNameLabel, const char* szLocation,
                     const char* szLocationLabel, const char* szFieldName,
                     const char* szSubFilter);

  void InitSignature(int pageIndex, float left, float bottom, float width,
                     float height, const char* szReason,
                     const char* szReasonLabel, const char* szName,
                     const char* szNameLabel, const char* szLocation,
                     const char* szLocationLabel, const char* szFieldName,
                     const char* szSubFilter);

  void InitSignature(int pageIndex, float left, float bottom, float width,
                     float height, const char* szReason,
                     const char* szReasonLabel, const char* szName,
                     const char* szNameLabel, const char* szLocation,
                     const char* szLocationLabel, const char* szFieldName,
                     const char* szSubFilter, const char* szImagePath,
                     const char* szDescription);

  void GetSignedPdf(UUCByteArray& signedPdf);

  double getWidth(int pageIndex);
  double getHeight(int pageIndex);


  std::unique_ptr<PoDoFo::PdfMemDocument> m_pPdfDocument;
  PoDoFo::PdfSignature* m_pSignatureField;
  std::unique_ptr<PoDoFo::BufferStreamDevice> m_pSignOutputDevice;

 private:
  PoDoFo::charbuff m_pOutputBuffer;
};

