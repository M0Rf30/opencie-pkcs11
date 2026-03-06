// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

#include "pdf_signature_generator.h"

#include <fstream>
#include <iostream>
#include <vector>

#include "pdf_verifier.h"

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

PdfSignatureGenerator::PdfSignatureGenerator() : m_pSignatureField(nullptr) {}

PdfSignatureGenerator::~PdfSignatureGenerator() = default;

int PdfSignatureGenerator::Load(const char* pdf, int len) {
  try {
    PoDoFo::PdfMemDocument tempDoc;
    tempDoc.LoadFromBuffer(PoDoFo::bufferview(pdf, len));

    m_pSignOutputDevice =
        std::make_shared<PoDoFo::BufferStreamDevice>(m_pOutputBuffer);
    tempDoc.Save(*m_pSignOutputDevice);

    m_pPdfDocument = std::make_unique<PoDoFo::PdfMemDocument>();
    m_pPdfDocument->Load(m_pSignOutputDevice);

    pfnCrashliticsLog("PdfSignatureGenerator::Load OK");
    return PDFVerifier::GetNumberOfSignatures(m_pPdfDocument.get());
  } catch (::PoDoFo::PdfError& err) {
    char msg[512];
    snprintf(msg, sizeof(msg),
             "PdfSignatureGenerator::Load PdfError code=%d: %s",
             static_cast<int>(err.GetCode()), err.what());
    pfnCrashliticsLog(msg);
    return -2;
  } catch (...) {
    pfnCrashliticsLog("PdfSignatureGenerator::Load unknown exception");
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
  float bottom0 = bottom * cropBoxHeight;

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

  if (width * height > 0) {
    PoDoFo::Rect localRect(0, 0, width0, height0);
    auto sigXObject = m_pPdfDocument->CreateXObjectForm(localRect);
    PoDoFo::PdfPainter painter;

    std::string signatureStamp;
    if (szName && szName[0]) signatureStamp.append(szName);
    if (szReason && szReason[0]) {
      signatureStamp.append("\n");
      signatureStamp.append(szReason);
    }

    bool streamOk = false;
    {
      PoDoFo::PdfPainter painter;
      try {
        painter.SetCanvas(*sigXObject);

        if (szImagePath && szImagePath[0]) {
          std::vector<char> imgBuffer;
          std::ifstream img(szImagePath,
                            std::ios::in | std::ios::binary | std::ios::ate);
          if (img.is_open()) {
            std::streampos imgBufferSize = img.tellg();
            imgBuffer.resize(static_cast<size_t>(imgBufferSize));
            img.seekg(0, std::ios::beg);
            img.read(imgBuffer.data(), imgBufferSize);
            img.close();

            if (!imgBuffer.empty()) {
              auto image = m_pPdfDocument->CreateImage();
              image->LoadFromBuffer(
                  PoDoFo::bufferview(imgBuffer.data(), imgBuffer.size()));
              double scaleX = width0 / image->GetWidth();
              double scaleY = height0 / image->GetHeight();
              painter.DrawImage(*image, 0, 0, std::min(scaleX, scaleY),
                                std::min(scaleX, scaleY));
            }
          }
        }

        if (!signatureStamp.empty()) {
          PoDoFo::PdfFont* font =
              m_pPdfDocument->GetFonts().SearchFont(FONT_NAME);
          if (font) {
            PoDoFo::Rect textRect(TXT_PAD, TXT_PAD, width0 - 2 * TXT_PAD,
                                  height0 - 2 * TXT_PAD);
            painter.TextState.SetFont(*font, FONT_SIZE);
            painter.DrawTextMultiLine(signatureStamp, textRect);
          }
        }

        streamOk = true;
      } catch (...) {
      }
      try {
        painter.FinishDrawing();
      } catch (...) {
        streamOk = false;
      }
    }

    if (streamOk) {
      try {
        m_pSignatureField->MustGetWidget().SetAppearanceStream(*sigXObject);
        try {
          m_pPdfDocument->GetAcroForm()->GetObject().GetDictionary().RemoveKey(
              PoDoFo::PdfName("DR"));
          m_pPdfDocument->GetAcroForm()->GetObject().GetDictionary().RemoveKey(
              PoDoFo::PdfName("DA"));
        } catch (...) {
        }
      } catch (...) {
      }
    }
  }
}

void PdfSignatureGenerator::GetSignedPdf(ByteDynArray& signedPdf) {
  int finalLength = m_pSignOutputDevice->GetLength();
  std::vector<char> szSignedPdf(finalLength);

  m_pSignOutputDevice->Seek(0);
  m_pSignOutputDevice->Read(szSignedPdf.data(), finalLength);
  signedPdf.append(
      ByteArray(reinterpret_cast<BYTE*>(szSignedPdf.data()), finalLength));
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
