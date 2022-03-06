// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

#include "pdf_signature_generator.h"

#include <fstream>
#include <iostream>
#include <vector>

#include "pdf_verifier.h"
#include "uuc_logger.h"

#define FONT_NAME "DejaVu Sans"
#define FONT_SIZE 5.0
#define TXT_PAD 5.5

#ifdef CreateFont
#undef CreateFont
#endif

#ifdef GetObject
#undef GetObject
#endif

int GetNumberOfSignatures(PoDoFo::PdfMemDocument* pPdfDocument);

USE_LOG;

PdfSignatureGenerator::PdfSignatureGenerator() : m_pSignatureField(nullptr) {}

PdfSignatureGenerator::~PdfSignatureGenerator() = default;

int PdfSignatureGenerator::Load(const char* pdf, int len) {
  try {
    m_pPdfDocument = std::make_unique<PoDoFo::PdfMemDocument>();

    // Copy pdf buffer for later use
    auto input = std::make_shared<PoDoFo::SpanStreamDevice>(
        PoDoFo::bufferview(pdf, len));
    m_pSignOutputDevice =
        std::make_unique<PoDoFo::BufferStreamDevice>(m_pOutputBuffer);
    input->CopyTo(*m_pSignOutputDevice);

    m_pPdfDocument->LoadFromBuffer(PoDoFo::bufferview(pdf, len));

    return PDFVerifier::GetNumberOfSignatures(m_pPdfDocument.get());
  } catch (::PoDoFo::PdfError& err) {
    return -2;
  } catch (...) {
    return -1;
  }
}

void PdfSignatureGenerator::InitSignature(
    int pageIndex, const char* szReason, const char* szReasonLabel,
    const char* szName, const char* szNameLabel, const char* szLocation,
    const char* szLocationLabel, const char* szFieldName,
    const char* szSubFilter) {
  LOG_DBG((0, "quella con tutti 0\n", ""));
  InitSignature(pageIndex, 0, 0, 0, 0, szReason, szReasonLabel, szName,
                szNameLabel, szLocation, szLocationLabel, szFieldName,
                szSubFilter);
}

void PdfSignatureGenerator::InitSignature(
    int pageIndex, float left, float bottom, float width, float height,
    const char* szReason, const char* szReasonLabel, const char* szName,
    const char* szNameLabel, const char* szLocation,
    const char* szLocationLabel, const char* szFieldName,
    const char* szSubFilter) {
  LOG_DBG((0, "quella senza tutti 0\n", ""));
  InitSignature(pageIndex, left, bottom, width, height, szReason, szReasonLabel,
                szName, szNameLabel, szLocation, szLocationLabel, szFieldName,
                szSubFilter, nullptr, nullptr);
}

void PdfSignatureGenerator::InitSignature(
    int pageIndex, float left, float bottom, float width, float height,
    const char* szReason, const char* /*szReasonLabel*/, const char* szName,
    const char* /*szNameLabel*/, const char* szLocation,
    const char* /*szLocationLabel*/, const char* szFieldName,
    const char* /*szSubFilter*/, const char* szImagePath,
    const char* /*szDescription*/) {
  auto& page = m_pPdfDocument->GetPages().GetPageAt(pageIndex);
  PoDoFo::Rect cropBox = page.GetCropBox();

  float cropBoxWidth = cropBox.Width;
  float cropBoxHeight = cropBox.Height;

  float left0 = left * cropBoxWidth;
  float bottom0 = cropBoxHeight - (bottom * cropBoxHeight);

  float width0 = width * cropBoxWidth;
  float height0 = height * cropBoxHeight;

  PoDoFo::Rect rect(left0, bottom0, width0, height0);

  m_pSignatureField = &page.CreateField<PoDoFo::PdfSignature>(
      PoDoFo::PdfString(szFieldName), rect);
  m_pSignatureField->EnsureValueObject();

  m_pSignatureField->MustGetWidget().SetFlags(
      static_cast<PoDoFo::PdfAnnotationFlags>(0x84));

  LOG_DBG((0, "InitSignature", "PdfSignatureField OK"));

  // This is the card holder's name
  // Shouldn't this go in /Name? Goes in /Reason
  if (szReason && szReason[0]) {
    PoDoFo::PdfString name(szReason);
    m_pSignatureField->SetSignatureReason(name);
  }

  LOG_DBG((0, "InitSignature", "szReason OK"));

  if (szLocation && szLocation[0]) {
    PoDoFo::PdfString location(szLocation);
    m_pSignatureField->SetSignatureLocation(location);
  }

  LOG_DBG((0, "InitSignature", "szLocation OK"));

  PoDoFo::PdfDate now = PoDoFo::PdfDate::LocalNow();
  m_pSignatureField->SetSignatureDate(now);

  LOG_DBG((0, "InitSignature", "Date OK"));

  // This is the signature date
  // Shouldn't this go in /M? Goes in /Name
  if (szName && szName[0]) {
    m_pSignatureField->SetSignerName(PoDoFo::PdfString(szName));
  }

  LOG_DBG((0, "InitSignature", "szName OK"));

  // Create graphical signature with stamp if we have a picture
  if (width * height > 0) {
    auto sigXObject = m_pPdfDocument->CreateXObjectForm(rect);
    PoDoFo::PdfPainter painter;

    try {
      std::vector<char> imgBuffer;
      double scale;
      std::streampos imgBufferSize = 0;
      std::ifstream img(szImagePath,
                        std::ios::in | std::ios::binary | std::ios::ate);
      std::string signatureStamp;
      auto image = m_pPdfDocument->CreateImage();

      // Copy the image in a buffer
      if (img.is_open()) {
        imgBufferSize = img.tellg();

        imgBuffer.resize(imgBufferSize);
        img.seekg(0, std::ios::beg);
        img.read(imgBuffer.data(), imgBufferSize);
        img.close();
      }

      // Generate signature string
      // Append date
      if (szName && szName[0]) signatureStamp.append(szName);

      // Append name
      if (szReason && szReason[0]) {
        signatureStamp.append("\n");
        signatureStamp.append(szReason);
      }

      image->LoadFromBuffer(
          PoDoFo::bufferview(imgBuffer.data(), imgBufferSize));
      scale = (width0 / image->GetWidth());

      // Draw signature
      painter.SetCanvas(*sigXObject);
      painter.Save();
      painter.Restore();
      painter.DrawImage(*image, left0, bottom0, scale, scale);

      // Create signature stamp
      PoDoFo::PdfFont* font = m_pPdfDocument->GetFonts().SearchFont(FONT_NAME);
      PoDoFo::Rect sigRect =
          PoDoFo::Rect(left0 + TXT_PAD, bottom0 - TXT_PAD, width0, height0);
      painter.TextState.SetFont(*font, FONT_SIZE);
      painter.DrawTextMultiLine(signatureStamp, sigRect);

      m_pSignatureField->MustGetWidget().SetAppearanceStream(*sigXObject);

      LOG_DBG((0, "InitSignature", "SetAppearanceStream OK"));

      // Remove the font we embedded
      m_pPdfDocument->GetAcroForm()->GetObject().GetDictionary().RemoveKey(
          PoDoFo::PdfName("DR"));
      m_pPdfDocument->GetAcroForm()->GetObject().GetDictionary().RemoveKey(
          PoDoFo::PdfName("DA"));
    } catch (...) {
    }

    painter.FinishDrawing();
  }
}

void PdfSignatureGenerator::GetSignedPdf(UUCByteArray& signedPdf) {
  int finalLength = m_pSignOutputDevice->GetLength();
  std::vector<char> szSignedPdf(finalLength);

  m_pSignOutputDevice->Seek(0);
  m_pSignOutputDevice->Read(szSignedPdf.data(), finalLength);
  signedPdf.append(reinterpret_cast<BYTE*>(szSignedPdf.data()), finalLength);
}

double PdfSignatureGenerator::getWidth(int pageIndex) {
  if (m_pPdfDocument) {
    return m_pPdfDocument->GetPages().GetPageAt(pageIndex).GetRect().Width;
  }
  return 0;
}

double PdfSignatureGenerator::getHeight(int pageIndex) {
  if (m_pPdfDocument) {
    return m_pPdfDocument->GetPages().GetPageAt(pageIndex).GetRect().Height;
  }
  return 0;
}
