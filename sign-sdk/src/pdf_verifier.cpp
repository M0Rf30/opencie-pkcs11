// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

#include <cstddef>
#include <sstream>
#ifndef HP_UX

#include <string>

// On Windows, windows.h defines GetObject/CreateFont macros that conflict
// with PoDoFo method names. Include PoDoFo headers first, then undef.
#include "pdf_verifier.h"

#ifdef GetObject
#undef GetObject
#endif

#include "asn1/signed_data.h"
#include "asn1/signer_info.h"
#include "signed_document.h"

extern logFunc pfnCrashliticsLog;

using namespace PoDoFo;

PDFVerifier::PDFVerifier() : m_actualLen(0) {}

PDFVerifier::~PDFVerifier() = default;

int PDFVerifier::Load(const char *pdf, int len) {
  m_pPdfMemDocument.reset();

  try {
    m_pPdfMemDocument = std::make_unique<PdfMemDocument>();
    m_pPdfMemDocument->LoadFromBuffer(bufferview(pdf, len));
    m_actualLen = len;
    m_szDocBuffer = const_cast<char *>(pdf);

    return 0;
  } catch (::PoDoFo::PdfError &err) {
    return -2;
  } catch (...) {
    return -1;
  }
}

int PDFVerifier::Load(const char *szFilePath) {
  m_pPdfMemDocument.reset();

  try {
    m_pPdfMemDocument = std::make_unique<PdfMemDocument>();
    m_pPdfMemDocument->Load(szFilePath);

    m_data.removeAll();

    {
      BYTE buffer[BUFFERSIZE];
      int nRead = 0;
      FILE *f = fopen(szFilePath, "rb");
      if (!f) {
        return DISIGON_ERROR_FILE_NOT_FOUND;
      }
      while ((nRead = fread(buffer, 1, BUFFERSIZE, f)) > 0) {
        m_data.append(buffer, nRead);
      }
      fclose(f);
    }
    m_actualLen = m_data.getLength();
    m_szDocBuffer = (char *)m_data.getContent();

    return 0;
  } catch (::PoDoFo::PdfError &err) {
    return -2;
  } catch (...) {
    return -1;
  }
}

int PDFVerifier::GetNumberOfSignatures(const char *szFilePath) {
  pfnCrashliticsLog("PDFVerifier::GetNumberOfSignatures");
  pfnCrashliticsLog(szFilePath);

  PdfMemDocument doc;

  try {
    doc.Load(szFilePath);

    pfnCrashliticsLog("file loaded");

    return GetNumberOfSignatures(&doc);
  } catch (::PoDoFo::PdfError &err) {
    return -2;
  } catch (...) {
    return -1;
  }
}

int PDFVerifier::GetNumberOfSignatures(PdfMemDocument *pPdfDocument) {
  /// Find the document catalog dictionary
  auto &acroForm = pPdfDocument->GetOrCreateAcroForm();
  const PdfObject *fieldsValue =
      acroForm.GetObject().GetDictionary().GetKey("Fields");
  if (fieldsValue->GetDataType() == PdfDataType::Reference)
    fieldsValue =
        pPdfDocument->GetObjects().GetObject(fieldsValue->GetReference());

  if (!fieldsValue || fieldsValue->GetDataType() != PdfDataType::Array)
    return 0;

  /// Verify if each object of the array is a signature field
  int n = 0;
  const PdfArray &array = fieldsValue->GetArray();
  for (const auto& elem : array) {
    const PdfObject *const obj =
        pPdfDocument->GetObjects().GetObject(elem.GetReference());
    if (IsSignatureField(pPdfDocument, obj)) {
      n++;
    }
  }

  return n;
}

int PDFVerifier::GetNumberOfSignatures() {
  if (!m_pPdfMemDocument) return -1;

  return GetNumberOfSignatures(m_pPdfMemDocument.get());
}

int PDFVerifier::VerifySignature(size_t index, const char *szDate,
                                 char *signatureType,
                                 REVOCATION_INFO *pRevocationInfo) {
  if (!m_pPdfMemDocument) return -1;

  /// Find the document catalog dictionary
  auto &acroForm = m_pPdfMemDocument->GetOrCreateAcroForm();
  const PdfObject *fieldsValue =
      acroForm.GetObject().GetDictionary().GetKey("Fields");
  if (fieldsValue->GetDataType() == PdfDataType::Reference)
    fieldsValue =
        m_pPdfMemDocument->GetObjects().GetObject(fieldsValue->GetReference());

  if (!fieldsValue || fieldsValue->GetDataType() != PdfDataType::Array)
    return 0;
  
  std::vector<const PdfObject *> signatureVector;

  /// Verify if each object of the array is a signature field
  const PdfArray &array = fieldsValue->GetArray();
  for (const auto& elem : array) {
    const PdfObject *pObj =
        m_pPdfMemDocument->GetObjects().GetObject(elem.GetReference());
    if (IsSignatureField(m_pPdfMemDocument.get(), pObj)) {
      signatureVector.push_back(pObj);
    }
  }

  if (index >= signatureVector.size()) return 0;

  const PdfObject *pSignatureObject = signatureVector[index];

  return VerifySignature(m_pPdfMemDocument.get(), pSignatureObject, szDate,
                         signatureType, pRevocationInfo);
}

int PDFVerifier::VerifySignature(const PdfMemDocument *pDoc,
                                 const PdfObject *const pObj,
                                 const char *szDate, char *signatureType,
                                 REVOCATION_INFO *pRevocationInfo) {
  if (pObj == 0) return false;

  if (!pObj->IsDictionary()) return -1;

  const PdfObject *const keyFTValue =
      pObj->GetDictionary().GetKey(PdfName("FT"));
  if (keyFTValue == 0) return -2;

  const PdfName value = keyFTValue->GetName();
  if (value != "Sig") return -3;

  const PdfObject *const keyVValue = pObj->GetDictionary().GetKey(PdfName("V"));
  if (keyVValue == 0) return -4;

  const PdfObject *const signature =
      pDoc->GetObjects().GetObject(keyVValue->GetReference());
  if (signature->IsDictionary()) {
    std::string byteRange;
    std::string signdData;
    std::string subfilter;

    const PdfObject *const keyByteRange =
        signature->GetDictionary().GetKey(PdfName("ByteRange"));
    keyByteRange->ToString(byteRange);

    const PdfObject *const keyContents =
        signature->GetDictionary().GetKey(PdfName("Contents"));
    keyContents->ToString(signdData);

    const PdfObject *const keySubFilter =
        signature->GetDictionary().GetKey(PdfName("SubFilter"));
    keySubFilter->ToString(subfilter);

    // PoDoFo 0.10+ adds an invisible trailing character that makes comparison
    // fail
    if (!subfilter.empty()) subfilter.pop_back();

    // Parse byteRange "[ start0 len0 start1 len1 ]" — strip brackets then parse ints
    std::string cleanRange = byteRange;
    for (char& c : cleanRange) {
      if (c == '[' || c == ']') c = ' ';
    }
    int _start0_unused, len, start1, len1;
    {
      std::istringstream brss(cleanRange);
      brss >> _start0_unused >> len >> start1 >> len1;
    }

    // Extract hex-encoded signed data between < and >
    auto ltPos = signdData.find('<');
    auto gtPos = signdData.rfind('>');
    std::string hexData = (ltPos != std::string::npos && gtPos != std::string::npos)
        ? signdData.substr(ltPos + 1, gtPos - ltPos - 1) : signdData;

    UUCByteArray baSignedData(hexData.c_str());
    CSignedDocument signedDocument(baSignedData.getContent(),
                                   baSignedData.getLength());

    CSignedData signedData(signedDocument.getSignedData());

    snprintf(signatureType, 256, "%s", subfilter.c_str());

    if (subfilter == "/adbe.pkcs7.detached" ||
        subfilter == "/ETSI.CAdES.detached") {
      // extract the actual content
      UUCByteArray baContent;
      baContent.append(reinterpret_cast<BYTE *>(m_szDocBuffer), len);
      baContent.append((reinterpret_cast<BYTE *>(m_szDocBuffer) + start1), len1);
      CASN1SetOf signerInfos = signedData.getSignerInfos();
      CSignerInfo signerInfo(signerInfos.elementAt(0));
      CASN1SetOf certificates = signedData.getCertificates();

      CASN1OctetString actualContent(baContent);

      return CSignerInfo::verifySignature(
          actualContent, signerInfo, certificates, szDate, pRevocationInfo);
    } else if (subfilter == "/adbe.pkcs7.sha1") {
      return signedData.verify(0, szDate, pRevocationInfo);

    } else {
      return -5;
    }

    // DONE:

    // extract the contents value

    // if subfilter is sha1
    // create a SignedDocument by the contents value
    // return SignedDocument.verify
    // else
    // Create a CSignedData by the contents value
    // creates the actual content by using ByteRange
    // return CSignedData.Verify (detached) passing the actual content
  } else
    return -6;
}

bool PDFVerifier::IsSignatureField(const PdfMemDocument *pDoc,
                                   const PdfObject *const pObj) {
  if (pObj == 0) return false;
  if (!pObj->IsDictionary()) return false;

  const PdfObject *const keyFTValue =
      pObj->GetDictionary().GetKey(PdfName("FT"));
  if (keyFTValue == 0) return false;

  const PdfName value = keyFTValue->GetName();
  if (value != "Sig") return false;

  const PdfObject *const keyVValue = pObj->GetDictionary().GetKey(PdfName("V"));
  if (keyVValue == 0) return false;

  const PdfObject *const signature =
      pDoc->GetObjects().GetObject(keyVValue->GetReference());
  if (signature->IsDictionary()) return true;
  return false;
}

int PDFVerifier::GetSignature(size_t index, UUCByteArray &signedDocument,
                              SignatureAppearanceInfo &signatureInfo) {
  if (!m_pPdfMemDocument) return -1;

  /// Find the document catalog dictionary
  auto &acroForm = m_pPdfMemDocument->GetOrCreateAcroForm();
  const PdfObject *fieldsValue =
      acroForm.GetObject().GetDictionary().GetKey("Fields");
  if (fieldsValue->GetDataType() == PdfDataType::Reference)
    fieldsValue =
        m_pPdfMemDocument->GetObjects().GetObject(fieldsValue->GetReference());

  if (!fieldsValue || fieldsValue->GetDataType() != PdfDataType::Array)
    return -7;

  std::vector<const PdfObject *> signatureVector;

  /// Verify if each object of the array is a signature field
  const PdfArray &array = fieldsValue->GetArray();
  for (const auto& elem : array) {
    const PdfObject *pObj =
        m_pPdfMemDocument->GetObjects().GetObject(elem.GetReference());
    if (IsSignatureField(m_pPdfMemDocument.get(), pObj)) {
      signatureVector.push_back(pObj);
    }
  }

  if (index >= signatureVector.size()) return -8;

  const PdfObject *pSignatureObject = signatureVector[index];

  return GetSignature(m_pPdfMemDocument.get(), pSignatureObject, signedDocument,
                      signatureInfo);
}

int PDFVerifier::GetSignature(const PdfMemDocument *pDoc,
                              const PdfObject *const pObj,
                              UUCByteArray &signedDocument,
                              SignatureAppearanceInfo &appearanceInfo) {
  if (pObj == 0) return -1;

  if (!pObj->IsDictionary()) return -1;

  const PdfObject *const keyFTValue =
      pObj->GetDictionary().GetKey(PdfName("FT"));
  if (keyFTValue == 0) return -2;

  const PdfName value = keyFTValue->GetName();
  if (value != "Sig") return -3;

  const PdfObject *const keyVValue = pObj->GetDictionary().GetKey(PdfName("V"));
  if (keyVValue == 0) return -4;

  const PdfObject *const keyRect =
      pObj->GetDictionary().GetKey(PdfName("Rect"));
  if (keyRect == 0) {
    return -4;
  }

  PdfArray rectArray = keyRect->GetArray();
  Rect rect;
  rect.FromArray(rectArray);

  appearanceInfo.left = rect.GetLeft();
  appearanceInfo.bottom = rect.GetBottom();
  appearanceInfo.width = rect.Width;
  appearanceInfo.heigth = rect.Height;

  const PdfObject *const signature =
      pDoc->GetObjects().GetObject(keyVValue->GetReference());
  if (signature->IsDictionary()) {
    std::string signdData;

    const PdfObject *const keyContents =
        signature->GetDictionary().GetKey(PdfName("Contents"));
    keyContents->ToString(signdData);

    auto ltPos2 = signdData.find('<');
    auto gtPos2 = signdData.rfind('>');
    std::string hexData2 = (ltPos2 != std::string::npos && gtPos2 != std::string::npos)
        ? signdData.substr(ltPos2 + 1, gtPos2 - ltPos2 - 1) : signdData;

    signedDocument.append(hexData2.c_str());
    return 0;
  } else
    return -6;
}

#endif
