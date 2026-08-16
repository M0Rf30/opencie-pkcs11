// SPDX-License-Identifier: LGPL-3.0-or-later
// DigitSign.cpp : Defines the exported functions for the DLL application.
//

#include "sign/cie_sign_api.h"

#ifdef _WIN32
// clang-format off
#include <winsock2.h>
#include <shlwapi.h>
// clang-format on
#endif

#include <libxml/tree.h>
#include <libxml/xmlmemory.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "asn1/asn1_exception.h"
#include "asn1/time_stamp_data.h"
#include "asn1/time_stamp_response.h"
#include "cert_store.h"
#include "cie_signer.h"
#include "crypto/base64.h"
#include "csp/ias.h"
#include "m7m_parser.h"
#include "pdf_signature_generator.h"
#include "pdf_verifier.h"
#include "properties.h"
#include "signature_generator.h"
#include "xades_generator.h"
#include "xades_verifier.h"

using namespace PoDoFo;

static long readFileIntoByteArray(const char* path, ByteDynArray& data) {
  BYTE buffer[BUFFERSIZE];
  int nRead = 0;
  FILE* f = fopen(path, "rb");
  if (!f) return CIE_SIGN_ERROR_FILE_NOT_FOUND;
  while ((nRead = fread(buffer, 1, BUFFERSIZE, f)) > 0)
    data.append(ByteArray(buffer, nRead));
  fclose(f);
  return 0;
}

static long writeByteArrayToFile(const char* path, const ByteDynArray& data) {
  FILE* f = fopen(path, "w+b");
  if (!f) return CIE_SIGN_ERROR_FILE_NOT_FOUND;
  fwrite(data.data(), 1, data.size(), f);
  fclose(f);
  return 0;
}

#define DEFAULT_VERIFY_REVOCATION 0
#define DEFAULT_VERIFY_USER_CERT 0

typedef struct _CIE_SIGN_CONTEXT {
  CBaseSigner* pSigner;
  CSignatureGenerator* pSignatureGenerator;
  char szInputFile[MAX_PATH];
  char szOutputFile[MAX_PATH];
  int nInputFileType;
  BOOL bDetached;
  BOOL bVerifyCert;
  char szPdfSubfilter[MAX_PATH];
  char szPdfReason[MAX_PATH];
  char szPdfName[MAX_PATH];
  char szPdfLocation[MAX_PATH];
  char szPdfReasonLabel[MAX_PATH];
  char szPdfNameLabel[MAX_PATH];
  char szPdfLocationLabel[MAX_PATH];
  int nPdfPage;
  float fPdfLeft;
  float fPdfBottom;
  float fPdfWidth;
  float fPdfHeight;
  const unsigned char* pPdfImageData;
  int nPdfImageDataLen;
  char szPdfDescription[MAX_PATH];
  IAS* pIAS;
  char szPIN[MAX_PATH];
  int nSlot;
  int nHashAlgo;
  char szAlias[MAX_PATH];
  char szTSAUrl[MAX_PATH];
  char szTSAUsername[MAX_PATH];
  char szTSAPassword[MAX_PATH];
  bool bCades;

} CIE_SIGN_CONTEXT;

class CIEPdfSigner : public PdfSigner {
 public:
  explicit CIEPdfSigner(CIE_SIGN_CONTEXT* pContext) : m_pContext(pContext) {}

 protected:
  void Reset() override { m_buffer.clear(); }

  void AppendData(const bufferview& data) override {
    m_buffer.append(data.data(), data.size());
  }

  void ComputeSignature(charbuff& buffer, bool dryrun) override;

  std::string GetSignatureFilter() const override { return "Adobe.PPKLite"; }

  std::string GetSignatureSubFilter() const override {
    return m_pContext->szPdfSubfilter;
  }

  std::string GetSignatureType() const override { return "Sig"; }

 private:
  charbuff m_buffer;
  CIE_SIGN_CONTEXT* m_pContext;
};

typedef struct _CIE_VERIFY_CONTEXT {
  char szInputFile[MAX_PATH];
  char szOutputFile[MAX_PATH];
  char szInputPlainTextFile[MAX_PATH];  // for detached
  int nInputFileType;
  BOOL bVerifyCRL;
} CIE_VERIFY_CONTEXT;

char g_szCACertDir[MAX_PATH];
bool g_bCACertDirSet = false;
char g_szVerifyProxy[MAX_PATH] = {0};
char* g_szVerifyProxyUsrPass = nullptr;
int g_nVerifyProxyPort = -1;

Properties g_mapOIDProps;

IAS* ias = nullptr;

int get_file_type(const char* szFileName);
long verifyTST(CTimeStampToken& tst, TS_INFO* pTSInfo, BOOL bVerifyCRL);

long verify_signed_document(CIE_VERIFY_CONTEXT* pContext, CSignedDocument& sd,
                            VERIFY_INFO* pVerifyInfo);
long verify_pdf(CIE_VERIFY_CONTEXT* pContext, VERIFY_INFO* pVerifyInfo);
long verify_p7m(CIE_VERIFY_CONTEXT* pContext, VERIFY_INFO* pVerifyInfo);
long verify_tsd(CIE_VERIFY_CONTEXT* pContext, VERIFY_INFO* pVerifyInfo);
long verify_tst(CIE_VERIFY_CONTEXT* pContext, VERIFY_INFO* pVerifyInfo);
long verify_tsr(CIE_VERIFY_CONTEXT* pContext, VERIFY_INFO* pVerifyInfo);
long verify_m7m(CIE_VERIFY_CONTEXT* pContext, VERIFY_INFO* pVerifyInfo);
long verify_xml(CIE_VERIFY_CONTEXT* pContext, VERIFY_INFO* pVerifyInfo);
long verify_pdf(CIE_VERIFY_CONTEXT* pContext, ByteDynArray& data,
                VERIFY_INFO* pVerifyInfo);

long sign_pdf(CIE_SIGN_CONTEXT* pContext, const ByteDynArray& data);
long sign_xml(CIE_SIGN_CONTEXT* pContext, const ByteDynArray& data);
long HTTPRequest(const ByteDynArray& data, const char* szUrl,
                 const char* szContentType, ByteDynArray& response);

const char* FILETYPE[] = {"PKCS7 file", "PDF file", "M7M file", "TSR file",
                          "TST file",   "TSD file", "XML file"};

long cie_sign_set(int option, void* value) {
  switch (option) {
    case CIE_SIGN_OPT_CACERT_DIR:
      LOG_DBG((0, "cie_sign_set", "set CIE_SIGN_OPT_CACERT_DIR: %s",
               static_cast<char*>(value)));
      snprintf(g_szCACertDir, MAX_PATH, "%s", static_cast<char*>(value));
      g_bCACertDirSet = true;
      break;

    case CIE_SIGN_OPT_LOG_FILE:
      SET_LOG_FILE(static_cast<char*>(value));
      break;

    case CIE_SIGN_OPT_LOG_LEVEL:
      SET_LOG_LEVEL(*(static_cast<int*>(value)));
      break;

    case CIE_SIGN_OPT_OID_MAP_FILE: {
      LOG_DBG((0, "cie_sign_set", "CIE_SIGN_OPT_OID_MAP_FILE: %s",
               static_cast<char*>(value)));
      long nRet = g_mapOIDProps.load(static_cast<char*>(value));
      if (nRet) return nRet;
    } break;
  }

  return 0;
}

long cie_sign_set_int(int option, int value) {
  int* valuePtr = new int(value);
  long result = cie_sign_set(option, reinterpret_cast<void*>(valuePtr));
  delete valuePtr;  // Clean up the allocated memory
  return result;
}

long cie_sign_set_string(int option, char* value) {
  return cie_sign_set(option, reinterpret_cast<void*>(value));
}

void cie_sign_cleanup() { CCertStore::CleanUp(); }

CIE_SIGN_CTX cie_sign_sign_init(void) {
  LOG_MSG((0, "--> cie_sign_sign_init", ""));

  CIE_SIGN_CONTEXT* pContext = new CIE_SIGN_CONTEXT;

  pContext->bDetached = 0;
  pContext->bVerifyCert = DEFAULT_VERIFY_USER_CERT;
  pContext->nInputFileType = CIE_SIGN_FILETYPE_PLAINTEXT;
  snprintf(pContext->szPdfSubfilter, MAX_PATH, "%s",
           CIE_SIGN_PDF_SUBFILTER_PKCS_DETACHED);
  pContext->szOutputFile[0] = 0;
  pContext->szInputFile[0] = 0;
  pContext->szPdfLocation[0] = '\0';
  pContext->szPdfReason[0] = '\0';
  pContext->szPdfName[0] = '\0';
  pContext->szPIN[0] = '\0';
  pContext->nSlot = -1;
  pContext->nHashAlgo = CKM_SHA256_RSA_PKCS;
  pContext->fPdfBottom = 0;
  pContext->fPdfLeft = 0;
  pContext->fPdfWidth = 0;
  pContext->fPdfHeight = 0;
  pContext->nPdfPage = 0;
  pContext->pPdfImageData = nullptr;
  pContext->nPdfImageDataLen = 0;
  pContext->szPdfDescription[0] = 0;
  snprintf(pContext->szPdfLocationLabel, MAX_PATH, "%s", "Signed by:");
  snprintf(pContext->szPdfReasonLabel, MAX_PATH, "%s", "Reason:");
  snprintf(pContext->szPdfLocationLabel, MAX_PATH, "%s", "Location:");
  pContext->szAlias[0] = 0;
  pContext->szTSAUrl[0] = 0;
  pContext->szTSAUsername[0] = 0;
  pContext->szTSAPassword[0] = 0;
  pContext->bCades = false;
  pContext->pSignatureGenerator = nullptr;
  pContext->pIAS = nullptr;

  if (g_mapOIDProps.size() == 0) g_mapOIDProps.load("OID.txt");

  LOG_MSG((0, "<-- cie_sign_sign_init", "Context: %p", pContext));

  return reinterpret_cast<CIE_SIGN_CTX>(pContext);
}

long cie_sign_sign_set_int(CIE_SIGN_CTX ctx, int option, int value) {
  int* valuePtr = new int(value);
  long result =
      cie_sign_sign_set(ctx, option, reinterpret_cast<void*>(valuePtr));
  delete valuePtr;  // Clean up the allocated memory
  return result;
}

long cie_sign_sign_set_string(CIE_SIGN_CTX ctx, int option, char* value) {
  return cie_sign_sign_set(ctx, option, reinterpret_cast<void*>(value));
}

long cie_sign_sign_set(CIE_SIGN_CTX ctx, int option, void* value) {
  LOG_MSG((0, "--> cie_sign_sign_set", "Context: %p, Option: %d", ctx, option));

  long nRet = 0;

  __TRY

  CIE_SIGN_CONTEXT* pContext = static_cast<CIE_SIGN_CONTEXT*>(ctx);

  switch (option) {
    case CIE_SIGN_OPT_IAS_INSTANCE:
      LOG_MSG((0, "cie_sign_sign_set", "Context: %p, Option: %s, Value: %s",
               ctx, "CIE_SIGN_OPT_IAS_INSTANCE", static_cast<char*>(value)));
      pContext->pIAS = static_cast<IAS*>(value);
      break;

    case CIE_SIGN_OPT_PIN:
      LOG_MSG((0, "cie_sign_sign_set", "Context: %p, Option: %s, Value: %s",
               ctx, "CIE_SIGN_OPT_PIN", "****"));
      snprintf(pContext->szPIN, MAX_PATH, "%s", static_cast<char*>(value));
      break;

    case CIE_SIGN_OPT_ALIAS:
      LOG_MSG((0, "cie_sign_sign_set", "Context: %p, Option: %s, Value: %s",
               ctx, "CIE_SIGN_OPT_ALIAS", static_cast<char*>(value)));
      snprintf(pContext->szAlias, MAX_PATH, "%s", static_cast<char*>(value));
      // pContext->pSignatureGenerator->SetAlias(static_cast<char*>(value));
      break;

    case CIE_SIGN_OPT_CADES:
      LOG_MSG((0, "cie_sign_sign_set", "Context: %p, Option: %s, Value: %d",
               ctx, "CIE_SIGN_OPT_CADES", (intptr_t)value));
      // pContext->pSignatureGenerator->SetCAdES((BOOL)(long)value);
      pContext->bCades = static_cast<BOOL>((intptr_t)value);
      break;

    case CIE_SIGN_OPT_INPUTFILE:
      LOG_MSG((0, "cie_sign_sign_set", "Context: %p, Option: %s, Value: %s",
               ctx, "CIE_SIGN_OPT_INPUTFILE", static_cast<char*>(value)));
      snprintf(pContext->szInputFile, MAX_PATH, "%s",
               static_cast<char*>(value));
      break;

    case CIE_SIGN_OPT_OUTPUTFILE:
      LOG_MSG((0, "cie_sign_sign_set", "Context: %p, Option: %s, Value: %s",
               ctx, "CIE_SIGN_OPT_OUTPUTFILE", static_cast<char*>(value)));
      snprintf(pContext->szOutputFile, MAX_PATH, "%s",
               static_cast<char*>(value));
      break;

    case CIE_SIGN_OPT_INPUTFILE_TYPE:
      LOG_MSG((0, "cie_sign_sign_set", "Context: %p, Option: %s, Value: %d",
               ctx, "CIE_SIGN_OPT_INPUTFILE_TYPE", (intptr_t)value));
      pContext->nInputFileType = (intptr_t)value;
      break;

    case CIE_SIGN_OPT_DETACHED:
      LOG_MSG((0, "cie_sign_sign_set", "Context: %p, Option: %s, Value: %d",
               ctx, "CIE_SIGN_OPT_DETACHED", (intptr_t)value));
      pContext->bDetached = static_cast<BOOL>((intptr_t)value);
      break;

    case CIE_SIGN_OPT_TSA_URL:
      LOG_MSG((0, "cie_sign_sign_set", "Context: %p, Option: %s, Value: %s",
               ctx, "CIE_SIGN_OPT_TSA_URL", static_cast<char*>(value)));
      snprintf(pContext->szTSAUrl, MAX_PATH, "%s", static_cast<char*>(value));
      // pContext->pSignatureGenerator->SetTSA(static_cast<char*>(value),
      // nullptr, nullptr);
      break;

    case CIE_SIGN_OPT_TSA_USERNAME:
      LOG_MSG((0, "cie_sign_sign_set", "Context: %p, Option: %s, Value: %s",
               ctx, "CIE_SIGN_OPT_TSA_USERNAME", static_cast<char*>(value)));
      snprintf(pContext->szTSAUsername, MAX_PATH, "%s",
               static_cast<char*>(value));
      // pContext->pSignatureGenerator->SetTSAUsername(static_cast<char*>(value));
      break;

    case CIE_SIGN_OPT_TSA_PASSWORD:
      LOG_MSG((0, "cie_sign_sign_set", "Context: %p, Option: %s, Value: %s",
               ctx, "CIE_SIGN_OPT_TSA_PASSWORD", static_cast<char*>(value)));
      snprintf(pContext->szTSAPassword, MAX_PATH, "%s",
               static_cast<char*>(value));
      break;

    case CIE_SIGN_OPT_PDF_SUBFILTER:
      LOG_MSG((0, "cie_sign_sign_set", "Context: %p, Option: %s, Value: %s",
               ctx, "CIE_SIGN_OPT_PDF_SUBFILTER", static_cast<char*>(value)));
      snprintf(pContext->szPdfSubfilter, MAX_PATH, "%s",
               static_cast<char*>(value));
      break;

    case CIE_SIGN_OPT_PDF_LOCATION:
      LOG_MSG((0, "cie_sign_sign_set", "Context: %p, Option: %s, Value: %s",
               ctx, "CIE_SIGN_OPT_LOCATION", static_cast<char*>(value)));
      snprintf(pContext->szPdfLocation, MAX_PATH, "%s",
               static_cast<char*>(value));
      break;

    case CIE_SIGN_OPT_PDF_NAME:
      LOG_MSG((0, "cie_sign_sign_set", "Context: %p, Option: %s, Value: %s",
               ctx, "CIE_SIGN_OPT_PDF_NAME", static_cast<char*>(value)));
      snprintf(pContext->szPdfName, MAX_PATH, "%s", static_cast<char*>(value));
      break;

    case CIE_SIGN_OPT_PDF_REASON:
      LOG_MSG((0, "cie_sign_sign_set", "Context: %p, Option: %s, Value: %s",
               ctx, "CIE_SIGN_OPT_PDF_REASON", static_cast<char*>(value)));
      snprintf(pContext->szPdfReason, MAX_PATH, "%s",
               static_cast<char*>(value));
      break;

    case CIE_SIGN_OPT_PDF_BOTTOM:
      LOG_MSG((0, "cie_sign_sign_set", "Context: %p, Option: %s, Value: %f",
               ctx, "CIE_SIGN_OPT_PDF_BOTTOM", *(static_cast<float*>(value))));
      pContext->fPdfBottom = *(static_cast<float*>(value));
      break;

    case CIE_SIGN_OPT_PDF_LEFT:
      LOG_MSG((0, "cie_sign_sign_set", "Context: %p, Option: %s, Value: %f",
               ctx, "CIE_SIGN_OPT_PDF_LEFT", *(static_cast<float*>(value))));
      pContext->fPdfLeft = *(static_cast<float*>(value));
      break;

    case CIE_SIGN_OPT_PDF_WIDTH:
      LOG_MSG((0, "cie_sign_sign_set", "Context: %p, Option: %s, Value: %f",
               ctx, "CIE_SIGN_OPT_PDF_WIDTH", *(static_cast<float*>(value))));
      pContext->fPdfWidth = *(static_cast<float*>(value));
      break;

    case CIE_SIGN_OPT_PDF_HEIGHT:
      LOG_MSG((0, "cie_sign_sign_set", "Context: %p, Option: %s, Value: %f",
               ctx, "CIE_SIGN_OPT_PDF_HEIGHT", *(static_cast<float*>(value))));
      pContext->fPdfHeight = *(static_cast<float*>(value));
      break;

    case CIE_SIGN_OPT_PDF_PAGE:
      LOG_MSG((0, "cie_sign_sign_set", "Context: %p, Option: %s, Value: %d",
               ctx, "CIE_SIGN_OPT_PDF_PAGE", *(static_cast<long*>(value))));
      pContext->nPdfPage = *(static_cast<long*>(value));
      break;

    case CIE_SIGN_OPT_PDF_IMAGEDATA:
      LOG_MSG((0, "cie_sign_sign_set", "Context: %p, Option: %s, Value: %p",
               ctx, "CIE_SIGN_OPT_PDF_IMAGEDATA", value));
      pContext->pPdfImageData = static_cast<const unsigned char*>(value);
      break;

    case CIE_SIGN_OPT_PDF_IMAGEDATA_LEN:
      LOG_MSG((0, "cie_sign_sign_set", "Context: %p, Option: %s, Value: %d",
               ctx, "CIE_SIGN_OPT_PDF_IMAGEDATA_LEN", (int)(intptr_t)value));
      pContext->nPdfImageDataLen = static_cast<int>((intptr_t)value);
      break;

    case CIE_SIGN_OPT_PDF_DESCRIPTION:
      LOG_MSG((0, "digitsign_sign_setopt", "Context: %p, Option: %s, Value: %s",
               ctx, "DIGITSIGN_OPT_PDF_DESCRIPTION",
               static_cast<char*>(value)));
      snprintf(pContext->szPdfDescription, MAX_PATH, "%s",
               static_cast<char*>(value));
      break;

    case CIE_SIGN_OPT_PDF_LOCATION_LABEL:
      LOG_MSG((0, "cie_sign_sign_set", "Context: %p, Option: %s, Value: %s",
               ctx, "CIE_SIGN_OPT_PDF_LOCATION_LABEL",
               static_cast<char*>(value)));
      snprintf(pContext->szPdfLocationLabel, MAX_PATH, "%s",
               static_cast<char*>(value));
      break;

    case CIE_SIGN_OPT_PDF_NAME_LABEL:
      LOG_MSG((0, "cie_sign_sign_set", "Context: %p, Option: %s, Value: %s",
               ctx, "CIE_SIGN_OPT_PDF_NAME_LABEL", static_cast<char*>(value)));
      snprintf(pContext->szPdfNameLabel, MAX_PATH, "%s",
               static_cast<char*>(value));
      break;

    case CIE_SIGN_OPT_PDF_REASON_LABEL:
      LOG_MSG((0, "cie_sign_sign_set", "Context: %p, Option: %s, Value: %s",
               ctx, "CIE_SIGN_OPT_PDF_REASON_LABEL",
               static_cast<char*>(value)));
      snprintf(pContext->szPdfReasonLabel, MAX_PATH, "%s",
               static_cast<char*>(value));
      break;

    case CIE_SIGN_OPT_VERIFY_USER_CERTIFICATE:
      LOG_MSG((0, "cie_sign_sign_set", "Context: %p, Option: %s, Value: %s",
               ctx, "CIE_SIGN_OPT_VERIFY_USER_CERTIFICATE",
               static_cast<char*>(value)));
      pContext->bVerifyCert = static_cast<BOOL>((intptr_t)value);
      break;
  }

  LOG_MSG((0, "<-- cie_sign_sign_set", "Returns %x", nRet));

  return nRet;

  __CATCH
}

void cie_sign_sign_freecertificates(CERTIFICATES* pCerts) {
  for (int i = 0; i < pCerts->nCount; i++) {
    CERTIFICATE cert = pCerts->pCertificate[i];
    SAFEDELETE(cert.pCertificate);
  }
}

long cie_sign_sign_sign(CIE_SIGN_CTX ctx) {
  LOG_MSG((0, "--> cie_sign_sign_sign", "Context: %p", ctx));
  LOG_MSG((0, "cie_sign_sign_sign", "Version: %s", "1.0.0"));

  __TRY

  CIE_SIGN_CONTEXT* pContext = static_cast<CIE_SIGN_CONTEXT*>(ctx);

  LOG_MSG((0, "--> cie_sign_sign_sign", "pContext: %p, pdf_left: %f", pContext,
           pContext->fPdfLeft));
  if (pContext->szInputFile[0] == 0) {
    LOG_ERR(
        (0, "cie_sign_sign_sign -> Error: CIE_SIGN_ERROR_INVALID_FILE", ""));
    return CIE_SIGN_ERROR_INVALID_FILE;
  }

  ByteDynArray data;
  if (readFileIntoByteArray(pContext->szInputFile, data) != 0) {
    LOG_ERR((0, "<-- cie_sign_sign_sign", "Context: %p, Error: %x, file: %s",
             pContext, CIE_SIGN_ERROR_FILE_NOT_FOUND, pContext->szInputFile));
    return CIE_SIGN_ERROR_FILE_NOT_FOUND;
  }

  LOG_DBG((0, "cie_sign_sign_sign", "Context: %p, Load P11", pContext));

  long nRes = 0;

  if (pContext->pIAS) {
    CCIESigner* pCIESigner = new CCIESigner(pContext->pIAS);
    long ret = pCIESigner->Init(pContext->szPIN);

    LOG_DBG((0, "CIESigner::Init", "ret %x", ret));

    if (ret != 0) {
      delete pCIESigner;
      pContext->pSigner = nullptr;
      pContext->pSignatureGenerator = nullptr;
      return ret;
    }

    pContext->pSigner = pCIESigner;
    pContext->pSignatureGenerator = new CSignatureGenerator(pContext->pSigner);

    LOG_DBG((0, "CIESigner::Init", "OK"));
  }

  if (pContext->szTSAUrl[0])
    pContext->pSignatureGenerator->SetTSA(pContext->szTSAUrl, nullptr, nullptr);

  if (pContext->szTSAUsername[0])
    pContext->pSignatureGenerator->SetTSAUsername(pContext->szTSAUsername);

  if (pContext->szTSAPassword[0])
    pContext->pSignatureGenerator->SetTSAPassword(pContext->szTSAPassword);

  if (pContext->szAlias[0])
    pContext->pSignatureGenerator->SetAlias(pContext->szAlias);

  pContext->pSignatureGenerator->SetCAdES(pContext->bCades);

  int nFileType = pContext->nInputFileType;

  if (nFileType == CIE_SIGN_FILETYPE_AUTO)
    nFileType = get_file_type(pContext->szInputFile);
  LOG_MSG((0, "--> cie_sign_sign_sign", "pContext: %p, pdf_left: %f", pContext,
           pContext->fPdfLeft));
  if (nFileType == CIE_SIGN_FILETYPE_PDF) {
    nRes = sign_pdf(pContext, data);
    return nRes;
  } else if (nFileType == CIE_SIGN_FILETYPE_P7M) {
    pContext->pSignatureGenerator->SetPKCS7Data(data);
  } else if (nFileType == CIE_SIGN_FILETYPE_XML) {
    nRes = sign_xml(pContext, data);
    return nRes;
  } else {
    LOG_DBG((0, "cie_sign_sign_sign", "Context: %p, SetData", pContext));
    pContext->pSignatureGenerator->SetData(data);
  }

  ByteDynArray signature;

  LOG_DBG((0, "cie_sign_sign_sign", "Context: %p, Sign", pContext));

  nRes = pContext->pSignatureGenerator->Generate(signature, pContext->bDetached,
                                                 pContext->bVerifyCert);
  if (nRes) {
    LOG_ERR((0, "<-- cie_sign_sign_sign", "Context: %p, Error: %x", pContext,
             nRes));
    return nRes;
  }

  if (pContext->szOutputFile[0] == 0) {
    snprintf(pContext->szOutputFile, sizeof(pContext->szOutputFile),
             "%.1019s.p7m", pContext->szInputFile);
  }

  LOG_DBG((0, "cie_sign_sign_sign", "Context: %p, Outputfile: %s", pContext,
           pContext->szOutputFile));

  if (writeByteArrayToFile(pContext->szOutputFile, signature) != 0) {
    LOG_ERR((0, "<-- cie_sign_sign_sign", "Context: %p, Error: %x, file: %s",
             pContext, CIE_SIGN_ERROR_FILE_NOT_FOUND, pContext->szOutputFile));
    return CIE_SIGN_ERROR_FILE_NOT_FOUND;
  }

  LOG_DBG((0, "<-- cie_sign_sign_sign", "Context: %p", pContext));

  return 0;

  __CATCH
}

long cie_sign_sign_cleanup(CIE_SIGN_CTX ctx) {
  LOG_MSG((0, "--> cie_sign_sign_cleanup", "Context: %p", ctx));

  __TRY

  CIE_SIGN_CONTEXT* pContext = static_cast<CIE_SIGN_CONTEXT*>(ctx);

  try {
    if (pContext->pSigner) pContext->pSigner->Close();
  } catch (...) {
  }

  SAFEDELETE(pContext->pSigner);
  SAFEDELETE(pContext->pSignatureGenerator);

  SAFEDELETE(pContext);

  return 0;

  __CATCH
}

CIE_SIGN_CTX cie_sign_verify_init(void) {
  LOG_MSG((0, "--> cie_sign_verify_init", ""));
  CIE_VERIFY_CONTEXT* pContext = new CIE_VERIFY_CONTEXT;

  pContext->szOutputFile[0] = '\0';
  pContext->bVerifyCRL = 0;
  pContext->nInputFileType = CIE_SIGN_FILETYPE_AUTO;
  pContext->szInputPlainTextFile[0] = '\0';
  pContext->szOutputFile[0] = 0;
  pContext->szInputFile[0] = 0;

  memset(g_szVerifyProxy, 0, MAX_PATH);

  if (g_szVerifyProxyUsrPass) {
    g_szVerifyProxyUsrPass = nullptr;
  }

  g_nVerifyProxyPort = -1;
  LOG_MSG((0, "<-- cie_sign_verify_init", "Context: %p", pContext));

  return reinterpret_cast<CIE_SIGN_CTX>(pContext);
}

long cie_sign_verify_set_int(CIE_SIGN_CTX ctx, int option, int value) {
  int* valuePtr = new int(value);
  long result =
      cie_sign_verify_set(ctx, option, reinterpret_cast<void*>(valuePtr));
  delete valuePtr;  // Clean up the allocated memory
  return result;
}

long cie_sign_verify_set_string(CIE_SIGN_CTX ctx, int option, char* value) {
  return cie_sign_verify_set(ctx, option, reinterpret_cast<void*>(value));
}

long cie_sign_verify_set(CIE_SIGN_CTX ctx, int option, void* value) {
  LOG_MSG((0, "--> cie_sign_verify_set", "Context: %p", ctx));

  __TRY

  CIE_VERIFY_CONTEXT* pContext = static_cast<CIE_VERIFY_CONTEXT*>(ctx);

  switch (option) {
    case CIE_SIGN_OPT_INPUTFILE:
      snprintf(pContext->szInputFile, MAX_PATH, "%s",
               static_cast<char*>(value));
      break;

    case CIE_SIGN_OPT_OUTPUTFILE:
      snprintf(pContext->szOutputFile, MAX_PATH, "%s",
               static_cast<char*>(value));
      break;

    case CIE_SIGN_OPT_VERIFY_REVOCATION:
      LOG_DBG((0, "cie_sign_verify_set", "Revocation: %d", (intptr_t)value));
      pContext->bVerifyCRL = static_cast<BOOL>((intptr_t)value);
      break;

    case CIE_SIGN_OPT_INPUTFILE_PLAINTEXT:
      snprintf(pContext->szInputPlainTextFile, MAX_PATH, "%s",
               static_cast<char*>(value));
      break;

    case CIE_SIGN_OPT_INPUTFILE_TYPE:
      pContext->nInputFileType = (intptr_t)value;
      break;

    case CIE_SIGN_OPT_PROXY:
      snprintf(g_szVerifyProxy, MAX_PATH, "%s", static_cast<char*>(value));
      LOG_DBG((0, "cie_sign_verify_set", "Proxy: %s", g_szVerifyProxy));
      if (g_nVerifyProxyPort == -1) g_nVerifyProxyPort = 0;
      break;

    case CIE_SIGN_OPT_PROXY_USRPASS:
      g_szVerifyProxyUsrPass = static_cast<char*>(value);
      LOG_DBG((0, "cie_sign_verify_set", "ProxyUsrPass: %s",
               g_szVerifyProxyUsrPass));
      break;

    case CIE_SIGN_OPT_PROXY_PORT:
      g_nVerifyProxyPort = (intptr_t)value;
      LOG_DBG((0, "cie_sign_verify_set", "ProxyPort: %d", g_nVerifyProxyPort));
      break;
  }

  return 0;

  __CATCH
}

long cie_sign_verify_verify(CIE_SIGN_CTX ctx, VERIFY_RESULT* pVerifyResult) {
  LOG_MSG((0, "--> cie_sign_verify_verify", "Context: %p", ctx));

  __TRY

  CIE_VERIFY_CONTEXT* pContext = static_cast<CIE_VERIFY_CONTEXT*>(ctx);

  if (pContext->szInputFile[0] == 0) {
    LOG_ERR((0, "cie_sign_verify_verify",
             "Context: %p, Error: CIE_SIGN_ERROR_INVALID_FILE"));
    return CIE_SIGN_ERROR_INVALID_FILE;
  }

  pVerifyResult->verifyInfo.pSignerInfos = nullptr;
  pVerifyResult->verifyInfo.pTSInfo = nullptr;

  int nFileType = pContext->nInputFileType;

  if (nFileType == CIE_SIGN_FILETYPE_AUTO)
    nFileType = get_file_type(pContext->szInputFile);

  LOG_DBG((0, "cie_sign_verify_verify", "Context: %p, FileType: %d", ctx,
           nFileType));

  snprintf(pVerifyResult->szInputFile, MAX_PATH, "%s", pContext->szInputFile);

  pVerifyResult->bVerifyCRL = pContext->bVerifyCRL;

  int nPos;

  long nRes = 0;
  switch (nFileType) {
    case CIE_SIGN_FILETYPE_P7M:
      pVerifyResult->nResultType = CIE_SIGN_FILETYPE_P7M;

      snprintf(pVerifyResult->szPlainTextFile, MAX_PATH, "%s",
               pContext->szInputFile);
      nPos = strlen(pContext->szInputFile) - 4;  // toglie l'ultima estensione
      pVerifyResult->szPlainTextFile[nPos] = 0;

      nRes = verify_p7m(pContext, &pVerifyResult->verifyInfo);
      break;

    case CIE_SIGN_FILETYPE_M7M:
      pVerifyResult->nResultType = CIE_SIGN_FILETYPE_M7M;

      snprintf(pVerifyResult->szPlainTextFile, MAX_PATH, "%s",
               pContext->szInputFile);
      nPos = strlen(pContext->szInputFile) - 4;  // toglie l'ultima estensione
      pVerifyResult->szPlainTextFile[nPos] = 0;

      nRes = verify_m7m(pContext, &pVerifyResult->verifyInfo);
      break;

    case CIE_SIGN_FILETYPE_PDF:
      pVerifyResult->nResultType = CIE_SIGN_FILETYPE_PDF;

      pVerifyResult->szPlainTextFile[0] = 0;

      nRes = verify_pdf(pContext, &pVerifyResult->verifyInfo);
      break;

    case CIE_SIGN_FILETYPE_TSD:
      pVerifyResult->nResultType = CIE_SIGN_FILETYPE_TSD;

      snprintf(pVerifyResult->szPlainTextFile, MAX_PATH, "%s",
               pContext->szInputFile);
      nPos = strlen(pContext->szInputFile) - 4;  // toglie l'ultima estensione
      pVerifyResult->szPlainTextFile[nPos] = 0;

      nRes = verify_tsd(pContext, &pVerifyResult->verifyInfo);
      break;

    case CIE_SIGN_FILETYPE_TSR:
      pVerifyResult->nResultType = CIE_SIGN_FILETYPE_TSR;

      pVerifyResult->szPlainTextFile[0] = 0;

      nRes = verify_tsr(pContext, &pVerifyResult->verifyInfo);
      break;

    case CIE_SIGN_FILETYPE_TST:
      pVerifyResult->nResultType = CIE_SIGN_FILETYPE_TST;

      pVerifyResult->szPlainTextFile[0] = 0;

      nRes = verify_tst(pContext, &pVerifyResult->verifyInfo);
      break;

    case CIE_SIGN_FILETYPE_XML:
      pVerifyResult->nResultType = CIE_SIGN_FILETYPE_XML;

      pVerifyResult->szPlainTextFile[0] = 0;

      nRes = verify_xml(pContext, &pVerifyResult->verifyInfo);
      break;

    default:
      LOG_ERR((0, "<-- cie_sign_verify_verify", "Context: %p, Error: %x",
               pContext, CIE_SIGN_ERROR_INVALID_FILE));
      nRes = CIE_SIGN_ERROR_INVALID_FILE;
      break;
  }

  pVerifyResult->nErrorCode = nRes;

  LOG_MSG((0, "<-- cie_sign_verify_verify", "Context: %px", pContext));

  return nRes;

  __CATCH
}

long cie_sign_verify_cleanup(CIE_SIGN_CTX ctx) {
  LOG_MSG((0, "--> cie_sign_verify_cleanup", "Context: %p", ctx));

  __TRY

  CIE_VERIFY_CONTEXT* pContext = static_cast<CIE_VERIFY_CONTEXT*>(ctx);

  SAFEDELETE(pContext);

  LOG_MSG((0, "<-- cie_sign_verify_cleanup", "Context: %p", ctx));

  return 0;

  __CATCH
}

// Recursively frees the nested heap allocations owned by a single
// SIGNER_INFO (its certificate blob, extension strings, revocation info,
// timestamp, and counter-signatures), but not `si` itself: `si` is always
// an element of a caller-owned SIGNER_INFO[] array or an embedded member.
static void freeSignerInfoContents(SIGNER_INFO& si) {
  delete[] si.pCertificate;
  si.pCertificate = nullptr;

  for (int j = 0; j < si.nExtensionsCount; j++) delete[] si.pszExtensions[j];
  delete[] si.pszExtensions;
  si.pszExtensions = nullptr;

  delete si.pRevocationInfo;
  si.pRevocationInfo = nullptr;

  if (si.pTimeStamp) {
    TS_INFO* pTSInfo = static_cast<TS_INFO*>(si.pTimeStamp);
    freeSignerInfoContents(pTSInfo->signerInfo);
    delete pTSInfo;
    si.pTimeStamp = nullptr;
  }

  if (si.pCounterSignatures) {
    SIGNER_INFO* pCounterSignatures =
        static_cast<SIGNER_INFO*>(si.pCounterSignatures);
    for (int k = 0; k < si.nCounterSignatureCount; k++)
      freeSignerInfoContents(pCounterSignatures[k]);
    delete[] pCounterSignatures;
    si.pCounterSignatures = nullptr;
    si.nCounterSignatureCount = 0;
  }
}

// Frees a SIGNER_INFOS array (and its own storage). `nInitialized` limits
// the deep content free to the first N entries; pass -1 (default) when
// every entry up to nCount has been populated. Use a smaller value on an
// error path where the array was allocated for more entries than were
// ever initialised.
static void freeSignerInfos(SIGNER_INFOS* pSignerInfos, int nInitialized = -1) {
  if (!pSignerInfos) return;
  int nCount = nInitialized < 0 ? pSignerInfos->nCount : nInitialized;
  for (int i = 0; i < nCount; i++)
    freeSignerInfoContents(pSignerInfos->pSignerInfo[i]);
  delete[] pSignerInfos->pSignerInfo;
  delete pSignerInfos;
}

// Frees the entire allocation tree referenced by a VERIFY_INFO: the
// per-signer array (with all nested certificates/extensions/revocation
// info/timestamps/counter-signatures) plus the top-level TS_INFO used by
// the standalone TSR/TST/TSD verification paths.
static void freeVerifyInfo(VERIFY_INFO& verifyInfo) {
  freeSignerInfos(verifyInfo.pSignerInfos);
  verifyInfo.pSignerInfos = nullptr;

  if (verifyInfo.pTSInfo) {
    freeSignerInfoContents(verifyInfo.pTSInfo->signerInfo);
    delete verifyInfo.pTSInfo;
    verifyInfo.pTSInfo = nullptr;
  }
}

long cie_sign_verify_cleanup_result(VERIFY_RESULT* pVerifyResult) {
  LOG_MSG((0, "--> cie_sign_verify_cleanup_result", "VerifyResult: %p",
           pVerifyResult));

  __TRY

  if (!pVerifyResult) return 0;

  freeVerifyInfo(pVerifyResult->verifyInfo);

  LOG_MSG((0, "<-- cie_sign_verify_cleanup_result", "VerifyResult: %p",
           pVerifyResult));
  return 0;

  __CATCH
}

long verify_p7m(CIE_VERIFY_CONTEXT* pContext, VERIFY_INFO* pVerifyInfo) {
  LOG_MSG((0, "--> verify_p7m", "Context: %p", pContext));

  ByteDynArray data;
  if (readFileIntoByteArray(pContext->szInputFile, data) != 0) {
    LOG_ERR((0, "<-- verify_p7m",
             "Context: %p, Error: CIE_SIGN_ERROR_FILE_NOT_FOUND, file: %s",
             pContext, pContext->szInputFile));
    return CIE_SIGN_ERROR_FILE_NOT_FOUND;
  }

  try {
    CSignedDocument sd(data.data(), data.size());

    if (sd.isDetached()) {
      if (pContext->szInputPlainTextFile[0] != '\0') {
        data.clear();
        if (readFileIntoByteArray(pContext->szInputPlainTextFile, data) != 0) {
          LOG_ERR(
              (0, "<-- verify_p7m",
               "Context: %p, Error: CIE_SIGN_ERROR_FILE_NOT_FOUND, file: %s",
               pContext, pContext->szInputPlainTextFile));
          return CIE_SIGN_ERROR_FILE_NOT_FOUND;
        }

        sd.setContent(data);
      } else {
        LOG_ERR((0, "<-- verify_p7m",
                 "Context: %p, Error: CIE_SIGN_ERROR_DETACHED_PKCS7, file: %s",
                 pContext, pContext->szInputFile));
        return CIE_SIGN_ERROR_DETACHED_PKCS7;
      }
    }

    long ret = verify_signed_document(pContext, sd, pVerifyInfo);

    if (ret != 0) return ret;

#ifdef WIN32
    if (StrStrIA(pContext->szInputFile, ".pdf."))
#else
    if (strcasestr(pContext->szInputFile, ".pdf."))
#endif
    {
      // pdf inside a P7M, check signature in the pdf

      ByteDynArray content;
      sd.getContent(content);

      VERIFY_INFO verifyInfo;

      ret = verify_pdf(pContext, content, &verifyInfo);
      if (ret != 0) return ret;

      int p7mSignatures = pVerifyInfo->pSignerInfos->nCount;
      int pdfSignatures = verifyInfo.pSignerInfos->nCount;

      SIGNER_INFOS* p7mSignerInfos = pVerifyInfo->pSignerInfos;
      SIGNER_INFOS* pdfSignerInfos = verifyInfo.pSignerInfos;

      TS_INFO* p7mTSInfo = pVerifyInfo->pTSInfo;
      // TS_INFO* pdfTSInfo = verifyInfo.pTSInfo;

      pVerifyInfo->pSignerInfos = new SIGNER_INFOS;
      pVerifyInfo->pSignerInfos->nCount = p7mSignatures + pdfSignatures;
      pVerifyInfo->pSignerInfos->pSignerInfo =
          new SIGNER_INFO[p7mSignatures + pdfSignatures];

      int i = 0;
      for (i = 0; i < p7mSignatures; i++) {
        pVerifyInfo->pSignerInfos->pSignerInfo[i] =
            p7mSignerInfos->pSignerInfo[i];
      }

      for (int j = 0; j < pdfSignatures; j++) {
        pVerifyInfo->pSignerInfos->pSignerInfo[i + j] =
            pdfSignerInfos->pSignerInfo[j];
      }

      pVerifyInfo->pTSInfo = p7mTSInfo;

      delete[] p7mSignerInfos->pSignerInfo;
      SAFEDELETE(p7mSignerInfos)
      delete[] pdfSignerInfos->pSignerInfo;
      SAFEDELETE(pdfSignerInfos)
    }

    return 0;
  } catch (...) {
    return CIE_SIGN_ERROR_INVALID_FILE;
  }
}

long cie_sign_get_file_from_p7m(CIE_SIGN_CTX ctx) {
  CIE_VERIFY_CONTEXT* pContext = static_cast<CIE_VERIFY_CONTEXT*>(ctx);

  LOG_MSG((0, "--> get_file_from_p7m", "Context: %p", pContext));

  int nFileType = pContext->nInputFileType;

  if (nFileType == CIE_SIGN_FILETYPE_AUTO)
    nFileType = get_file_type(pContext->szInputFile);

  if (nFileType != CIE_SIGN_FILETYPE_P7M) return CIE_SIGN_ERROR_INVALID_FILE;

  ByteDynArray data;
  if (readFileIntoByteArray(pContext->szInputFile, data) != 0) {
    LOG_ERR((0, "<-- get_file_from_p7m",
             "Context: %p, Error: CIE_SIGN_ERROR_FILE_NOT_FOUND, file: %s",
             pContext, pContext->szInputFile));
    return CIE_SIGN_ERROR_FILE_NOT_FOUND;
  }

  try {
    CSignedDocument sd(data.data(), data.size());

    ByteDynArray content;
    sd.getContent(content);

    if (writeByteArrayToFile(pContext->szOutputFile, content) != 0) {
      LOG_ERR((0, "<-- get_file_from_p7m - output file",
               "Context: %p, Error: QDIGITSIGN_ERROR_FILE_NOT_FOUND, file: %s",
               pContext, pContext->szOutputFile));
      return CIE_SIGN_ERROR_FILE_NOT_FOUND;
    }

    return 0;
  } catch (...) {
    return CIE_SIGN_ERROR_INVALID_FILE;
  }
}

long verify_xml(CIE_VERIFY_CONTEXT* pContext, VERIFY_INFO* pVerifyInfo) {
  LOG_MSG((0, "--> verify_xml", "Context: %p", pContext));

  ByteDynArray data;

  CXAdESVerifier verifier;

  long loadResult = verifier.Load(pContext->szInputFile);
  LOG_DBG((0, "verify_xml", "Load result: %ld", loadResult));
  if (loadResult < 0 || loadResult >= static_cast<long>(0x80000000L)) {
    LOG_ERR((0, "verify_xml", "Load failed with error: %lx", loadResult));
    return loadResult;
  }
  int signatureCount = (int)loadResult;

  pVerifyInfo->pSignerInfos = new SIGNER_INFOS;
  pVerifyInfo->pSignerInfos->nCount = signatureCount;

  // pVerifyInfo->pSignerInfos->pSignerInfo = new SIGNER_INFO*;
  pVerifyInfo->pSignerInfos->pSignerInfo = new SIGNER_INFO[signatureCount];

  for (int i = 0; i < signatureCount; i++) {
    CCertificate* pCert = verifier.GetCertificate(i);

    // SIGNER_INFO* pSI = new SIGNER_INFO;
    SIGNER_INFO* pSI = &(pVerifyInfo->pSignerInfos->pSignerInfo[i]);

    pSI->pCounterSignatures = nullptr;
    pSI->nCounterSignatureCount = 0;
    pSI->szSigningTime[0] = '\0';
    pSI->pRevocationInfo = nullptr;
    pSI->pTimeStamp = nullptr;
    pSI->b2011Error = false;

    CASN1ObjectIdentifier digestOID = verifier.GetDigestAlgorithm(i);
    ByteDynArray oid;
    digestOID.ToOidString(oid);
    snprintf(pSI->szDigestAlgorithm, MAX_LEN, "%s",
             reinterpret_cast<char*>(oid.data()));

    if (pContext->bVerifyCRL) pSI->pRevocationInfo = new REVOCATION_INFO;

    pSI->bitmask = verifier.verifySignature(i, nullptr, pSI->pRevocationInfo);

    std::string giveName = pCert->getSubject().getField(OID_GIVEN_NAME);
    std::string surname = pCert->getSubject().getField(OID_SURNAME);
    std::string commonName = pCert->getSubject().getField(OID_COMMON_NAME);

    snprintf(pSI->szCN, MAX_LEN * 2, "%s", commonName.c_str());
    snprintf(pSI->szGIVENNAME, MAX_LEN * 2, "%s", giveName.c_str());
    snprintf(pSI->szSURNAME, MAX_LEN * 2, "%s", surname.c_str());

    ByteDynArray subject;
    pCert->getSubject().getNameAsString(subject);

    snprintf(pSI->szDN, MAX_LEN * 2, "%s",
             reinterpret_cast<char*>(subject.data()));
    snprintf(pSI->szSN, MAX_LEN * 2, "%s",
             dumpHexData(*(const_cast<ByteDynArray*>(
                             pCert->getSerialNumber().getValue())))
                 .c_str());

    CASN1Sequence certExtensions(pCert->getExtensions());
    CASN1Sequence extensions(certExtensions.elementAt(0));
    int count = extensions.size();
    pSI->nExtensionsCount = count;
    pSI->pszExtensions = new char*[count];
    for (int j = 0; j < count; j++) {
      CASN1Sequence extension(extensions.elementAt(j));
      CASN1ObjectIdentifier extoid(extension.elementAt(0));
      CASN1OctetString value(extension.elementAt(1));
      ByteDynArray oidName;
      extoid.ToOidString(oidName);
      const char* szoid =
          g_mapOIDProps.getProperty(reinterpret_cast<char*>(oidName.data()),
                                    reinterpret_cast<char*>(oidName.data()));
      std::string hexvalStr =
          dumpHexData(*(const_cast<ByteDynArray*>(value.getValue())));
      const char* hexval = hexvalStr.c_str();
      char* szAux = new char[strlen(szoid) + strlen(hexval) + 5];
      snprintf(szAux, strlen(szoid) + strlen(hexval) + 5, "%s:%s", szoid,
               hexval);
      pSI->pszExtensions[j] = new char[strlen(szAux) + 1];
      snprintf(pSI->pszExtensions[j], MAX_LEN * 2, "%s", szAux);
      delete[] szAux;
    }

    ByteDynArray issuer;
    pCert->getIssuer().getNameAsString(issuer);
    snprintf(pSI->szCADN, MAX_LEN * 2, "%s",
             reinterpret_cast<char*>(issuer.data()));

    pCert->getExpiration().getUTCTime(pSI->szExpiration);
    pCert->getFrom().getUTCTime(pSI->szValidFrom);

    ByteDynArray certificate;
    pCert->toByteArray(certificate);

    pSI->nCertLen = certificate.size();
    pSI->pCertificate = new BYTE[pSI->nCertLen];
    memcpy(pSI->pCertificate, certificate.data(), pSI->nCertLen);
  }

  LOG_MSG((0, "<-- verify_xml", "Context: %p", pContext));

  return 0;
}

long verify_m7m(CIE_VERIFY_CONTEXT* pContext, VERIFY_INFO* pVerifyInfo) {
  LOG_MSG((0, "--> verify_m7m", "Context: %p", pContext));

  ByteDynArray data;
  if (readFileIntoByteArray(pContext->szInputFile, data) != 0) {
    LOG_ERR((0, "<-- verify_m7m",
             "Context: %p, Error: CIE_SIGN_ERROR_FILE_NOT_FOUND, file: %s",
             pContext, pContext->szInputFile));
    return CIE_SIGN_ERROR_FILE_NOT_FOUND;
  }

  M7MParser m7mParser;

  int nRes = m7mParser.Load(reinterpret_cast<char*>(data.data()), data.size());
  if (nRes) return nRes;

  ByteDynArray p7mData;
  nRes = m7mParser.GetP7M(p7mData);
  if (nRes) return nRes;

  ByteDynArray tsrData;
  nRes = m7mParser.GetTSR(tsrData);
  if (nRes) return nRes;

  CSignedDocument sd(p7mData.data(), p7mData.size());

  if (sd.isDetached()) {
    if (pContext->szInputPlainTextFile[0] != '\0') {
      ByteDynArray fileData;
      if (readFileIntoByteArray(pContext->szInputPlainTextFile, fileData) !=
          0) {
        LOG_ERR((0, "<-- verify_m7m",
                 "Context: %p, Error: CIE_SIGN_ERROR_FILE_NOT_FOUND, file: %s",
                 pContext, pContext->szInputPlainTextFile));
        return CIE_SIGN_ERROR_FILE_NOT_FOUND;
      }

      sd.setContent(fileData);
    } else {
      LOG_ERR((0, "<-- verify_m7m",
               "Context: %p, Error: CIE_SIGN_ERROR_DETACHED_PKCS7, file: %s",
               pContext, pContext->szInputFile));
      return CIE_SIGN_ERROR_DETACHED_PKCS7;
    }
  }

  nRes = verify_signed_document(pContext, sd, pVerifyInfo);
  if (nRes) {
    LOG_ERR((0, "<-- verify_m7m", "Context: %p, Error: %x", pContext, nRes));
    return nRes;
  }

  pVerifyInfo->pTSInfo = new TS_INFO;

  BufferedReader reader(tsrData);
  CTimeStampResponse tsr(reader);
  CTimeStampToken tst(tsr.getTimeStampToken());

  return verifyTST(tst, pVerifyInfo->pTSInfo, pContext->bVerifyCRL);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Winfinite-recursion"
int getEmbeddedSignatureCount(CSignedDocument& sd) {
  LOG_DBG((0, "--> getEmbeddedSignatureCount", ""));

  ByteDynArray content;
  sd.getContent(content);

  try {
    // LOG_DBG((0, "getEmbeddedSignatureCount", "Create SignedDocument"));

    const BYTE* bt = content.data();
    int len = content.size();

    CSignedDocument sd1(bt, len);

    int n = sd.getSignerCount() + getEmbeddedSignatureCount(sd1);

    LOG_DBG((0, "getEmbeddedSignatureCount", "Signature count: %d", n));

    return n;
  } catch (...) {
    LOG_DBG((0, "getEmbeddedSignatureCount", "Not embedded signature"));

    int n = sd.getSignerCount();

    LOG_DBG((0, "getEmbeddedSignatureCount", "Signature Count: %d", n));

    return n;
  }
}
#pragma GCC diagnostic pop

SIGNER_INFO* verify_countersignature(CIE_VERIFY_CONTEXT* pContext,
                                     CSignerInfo& si, CASN1SetOf& certificates,
                                     SIGNER_INFO* pSignerInfo,
                                     VERIFY_INFO* pVerifyInfo) {
  LOG_DBG((0, "--> verify_countersignature", ""));

  int counterSignatureCount = si.getCountersignatureCount();
  if (counterSignatureCount > 0) {
    CASN1SetOf counterSignatures = si.getCountersignatures();

    pSignerInfo->pCounterSignatures = new SIGNER_INFO[counterSignatureCount];
    pSignerInfo->nCounterSignatureCount = counterSignatureCount;

    for (int i = 0; i < counterSignatureCount; i++) {
      CSignerInfo counterSignature(counterSignatures.elementAt(i));

      CCertificate cert =
          CSignerInfo::getSignatureCertificate(counterSignature, certificates);

      SIGNER_INFO* pSI =
          &((static_cast<SIGNER_INFO*>(pSignerInfo->pCounterSignatures))[i]);
      pSI->pTimeStamp = nullptr;
      pSI->pCounterSignatures = nullptr;
      pSI->nCounterSignatureCount = 0;
      pSI->pRevocationInfo = nullptr;
      if (pContext->bVerifyCRL) pSI->pRevocationInfo = new REVOCATION_INFO;

      pSI->bitmask = si.verifyCountersignature(i, certificates, nullptr,
                                               pSI->pRevocationInfo);

      LOG_DBG(
          (0, "verify_countersignature", "verify result: %x", pSI->bitmask));

      ByteDynArray issuer;
      cert.getIssuer().getNameAsString(issuer);

      ByteDynArray subject;
      cert.getSubject().getNameAsString(subject);

      std::string giveName = cert.getSubject().getField(OID_GIVEN_NAME);
      std::string surname = cert.getSubject().getField(OID_SURNAME);
      std::string commonName = cert.getSubject().getField(OID_COMMON_NAME);

      snprintf(pSI->szCN, MAX_LEN * 2, "%s", commonName.c_str());
      snprintf(pSI->szGIVENNAME, MAX_LEN * 2, "%s", giveName.c_str());
      snprintf(pSI->szSURNAME, MAX_LEN * 2, "%s", surname.c_str());

      snprintf(pSI->szDN, MAX_LEN * 2, "%s",
               reinterpret_cast<char*>(subject.data()));

      snprintf(pSI->szSN, MAX_LEN * 2, "%s",
               dumpHexData(*(const_cast<ByteDynArray*>(
                               cert.getSerialNumber().getValue())))
                   .c_str());

      snprintf(pSI->szCADN, MAX_LEN * 2, "%s",
               reinterpret_cast<char*>(issuer.data()));

      CASN1ObjectIdentifier digestOID(si.getDigestAlgorithn().elementAt(0));
      ByteDynArray oid;
      digestOID.ToOidString(oid);
      snprintf(pSI->szDigestAlgorithm, MAX_LEN, "%s",
               reinterpret_cast<char*>(oid.data()));

      CASN1Sequence certExtensions(cert.getExtensions());
      CASN1Sequence extensions(certExtensions.elementAt(0));
      int count = extensions.size();
      pSI->nExtensionsCount = count;
      pSI->pszExtensions = new char*[count];
      for (int j = 0; j < count; j++) {
        CASN1Sequence extension(extensions.elementAt(j));
        CASN1ObjectIdentifier extoid(extension.elementAt(0));
        CASN1OctetString value(extension.elementAt(1));

        ByteDynArray oidName;
        extoid.ToOidString(oidName);
        const char* szoid =
            g_mapOIDProps.getProperty(reinterpret_cast<char*>(oidName.data()),
                                      reinterpret_cast<char*>(oidName.data()));
        std::string hexvalStr =
            dumpHexData(*(const_cast<ByteDynArray*>(value.getValue())));
        const char* hexval = hexvalStr.c_str();
        char* szAux = new char[strlen(szoid) + strlen(hexval) + 5];
        snprintf(szAux, strlen(szoid) + strlen(hexval) + 5, "%s:%s", szoid,
                 hexval);
        pSI->pszExtensions[j] = new char[strlen(szAux) + 1];
        snprintf(pSI->pszExtensions[j], MAX_LEN * 2, "%s", szAux);
        delete[] szAux;
      }

      cert.getExpiration().getUTCTime(pSI->szExpiration);
      cert.getFrom().getUTCTime(pSI->szValidFrom);

      ByteDynArray certificate;
      cert.toByteArray(certificate);

      pSI->nCertLen = certificate.size();
      pSI->pCertificate = new BYTE[pSI->nCertLen];
      memcpy(pSI->pCertificate, certificate.data(), pSI->nCertLen);

      snprintf(pSI->szSigningTime, MAX_LEN, "%s", "");

      try {
        CASN1UTCTime signingTime = si.getSigningTime();

        char szTime[MAX_LEN];
        signingTime.getUTCTime(szTime);
        snprintf(pSI->szSigningTime, MAX_LEN, "%s", szTime);

        pSI->b2011Error = (!(pSI->bitmask & VERIFIED_CERT_SHA256)) &&
                          (strncmp(szTime, "110630", 6) > 0);

      } catch (...) {
        snprintf(pSI->szSigningTime, MAX_LEN, "%s", "");
        pSI->b2011Error = false;
      }

      snprintf(pSI->szCertificateV2, MAX_LEN, "%s",
               szSHA256OID);  // default value

      if (si.hasTimeStampToken()) {
        LOG_DBG((0, "verify_signed_document 2", "Has TimeStamp"));

        CTimeStampToken tst = si.getTimeStampToken();

        TS_INFO* pTSInfo = new TS_INFO;

        CCertificate tsacert(tst.getCertificates().elementAt(0));

        ByteDynArray subject2;
        ByteDynArray issuer2;

        tsacert.getSubject().getNameAsString(subject2);
        tsacert.getIssuer().getNameAsString(issuer2);

        snprintf(pTSInfo->signerInfo.szDN, MAX_LEN * 2, "%s",
                 reinterpret_cast<char*>(subject2.data()));
        snprintf(pTSInfo->signerInfo.szCADN, MAX_LEN * 2, "%s",
                 reinterpret_cast<char*>(issuer2.data()));

        CTSTInfo tstInfo(tst.getTSTInfo());

        snprintf(pTSInfo->signerInfo.szSN, MAX_LEN * 2, "%s",
                 dumpHexData(*(const_cast<ByteDynArray*>(
                                 cert.getSerialNumber().getValue())))
                     .c_str());
        snprintf(pTSInfo->szTimeStampSerial, MAX_LEN, "%s",
                 dumpHexData(*(const_cast<ByteDynArray*>(
                                 tstInfo.getSerialNumber().getValue())))
                     .c_str());

        tstInfo.getUTCTime().getUTCTime(pTSInfo->szTimestamp);

        tsacert.getExpiration().getUTCTime(pTSInfo->signerInfo.szExpiration);
        tsacert.getFrom().getUTCTime(pTSInfo->signerInfo.szValidFrom);

        const ByteDynArray* certificate2 =
            const_cast<ByteDynArray*>(tsacert.getValue());

        pTSInfo->signerInfo.nCertLen = certificate2->size();
        pTSInfo->signerInfo.pCertificate =
            new BYTE[pTSInfo->signerInfo.nCertLen];
        memcpy(pTSInfo->signerInfo.pCertificate, certificate2->data(),
               pTSInfo->signerInfo.nCertLen);

        pTSInfo->signerInfo.pRevocationInfo = nullptr;
        if (pContext->bVerifyCRL)
          pTSInfo->signerInfo.pRevocationInfo = new REVOCATION_INFO;

        pTSInfo->signerInfo.bitmask =
            tst.verify(pTSInfo->signerInfo.pRevocationInfo);

        // MessageImprint
        CASN1Sequence messageImprint = tstInfo.getMessageImprint();

        // algo
        CAlgorithmIdentifier algoid(messageImprint.elementAt(0));
        CASN1ObjectIdentifier timeStampImprintAlgorithm(algoid.elementAt(0));

        ByteDynArray oid1;
        timeStampImprintAlgorithm.ToOidString(oid1);
        snprintf(pTSInfo->szTimeStampImprintAlgorithm, MAX_LEN, "%s",
                 reinterpret_cast<char*>(oid1.data()));

        // imprint b64
        CASN1OctetString mimprint(messageImprint.elementAt(1));
        const ByteDynArray* val = mimprint.getValue();

        ByteArray ba(const_cast<BYTE*>(val->data()), val->size());
        std::string b64Encoded;
        CBase64().Encode(ba, b64Encoded);

        snprintf(pTSInfo->szTimeStampMessageImprint, MAX_LEN, "%s",
                 b64Encoded.c_str());

        // digest algo
        CASN1ObjectIdentifier digestOID2(
            tstInfo.getDigestAlgorithn().elementAt(0));
        ByteDynArray oid2;
        digestOID2.ToOidString(oid2);
        snprintf(pTSInfo->signerInfo.szDigestAlgorithm, MAX_LEN, "%s",
                 reinterpret_cast<char*>(oid2.data()));
        pSI->pTimeStamp = pTSInfo;
      } else {
        LOG_DBG((0, "verify_signed_document 2", "Doesn't Have TimeStamp"));

        pSI->pTimeStamp = nullptr;
      }

      if (counterSignature.getCountersignatureCount() > 0) {
        verify_countersignature(pContext, counterSignature, certificates, pSI,
                                pVerifyInfo);
      }

      LOG_DBG((0, "verify_countersignature", "Set SI: %d", i));
    }
  }

  LOG_DBG((0, "--> verify_countersignature", ""));

  return 0;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Winfinite-recursion"
long verify_signed_document(int index, CIE_VERIFY_CONTEXT* pContext,
                            CSignedDocument& sd, VERIFY_INFO* pVerifyInfo) {
  LOG_DBG((0, "--> verify_signed_document 2", "Index: %d", index));

  int sigCount = sd.getSignerCount();

  LOG_DBG((0, "verify_signed_document 2", "sigCount: %d", sigCount));

  for (int i = 0; i < sigCount; i++) {
    CCertificate cert = sd.getSignerCertificate(i);

    CSignerInfo si = sd.getSignerInfo(i);

    SIGNER_INFO* pSI =
        &(pVerifyInfo->pSignerInfos->pSignerInfo[index]);  // = pSI;

    pSI->pTimeStamp = nullptr;
    pSI->pCounterSignatures = nullptr;
    pSI->nCounterSignatureCount = 0;
    pSI->pRevocationInfo = nullptr;
    if (pContext->bVerifyCRL) pSI->pRevocationInfo = new REVOCATION_INFO;

    pSI->bitmask =
        sd.verify(i, pSI->pRevocationInfo);  // pContext->bVerifyCRL);

    LOG_DBG((0, "verify_signed_document 2", "verify result: %x", pSI->bitmask));

    ByteDynArray issuer;
    cert.getIssuer().getNameAsString(issuer);

    ByteDynArray subject;
    cert.getSubject().getNameAsString(subject);

    std::string giveName = cert.getSubject().getField(OID_GIVEN_NAME);
    std::string surname = cert.getSubject().getField(OID_SURNAME);
    std::string commonName = cert.getSubject().getField(OID_COMMON_NAME);

    snprintf(pSI->szCN, MAX_LEN * 2, "%s", commonName.c_str());
    snprintf(pSI->szGIVENNAME, MAX_LEN * 2, "%s", giveName.c_str());
    snprintf(pSI->szSURNAME, MAX_LEN * 2, "%s", surname.c_str());

    snprintf(pSI->szDN, MAX_LEN * 2, "%s",
             reinterpret_cast<char*>(subject.data()));

    snprintf(pSI->szSN, MAX_LEN * 2, "%s",
             dumpHexData(*(const_cast<ByteDynArray*>(
                             cert.getSerialNumber().getValue())))
                 .c_str());

    snprintf(pSI->szCADN, MAX_LEN * 2, "%s",
             reinterpret_cast<char*>(issuer.data()));

    CASN1ObjectIdentifier digestOID(si.getDigestAlgorithn().elementAt(0));
    ByteDynArray oid;
    digestOID.ToOidString(oid);
    snprintf(pSI->szDigestAlgorithm, MAX_LEN, "%s",
             reinterpret_cast<char*>(oid.data()));

    CASN1Sequence certExtensions(cert.getExtensions());
    CASN1Sequence extensions(certExtensions.elementAt(0));
    int count = extensions.size();
    pSI->nExtensionsCount = count;
    pSI->pszExtensions = new char*[count];
    for (int j = 0; j < count; j++) {
      CASN1Sequence extension(extensions.elementAt(j));
      CASN1ObjectIdentifier extoid(extension.elementAt(0));
      CASN1OctetString value(extension.elementAt(1));

      ByteDynArray oidName;
      extoid.ToOidString(oidName);
      const char* szoid =
          g_mapOIDProps.getProperty(reinterpret_cast<char*>(oidName.data()),
                                    reinterpret_cast<char*>(oidName.data()));
      std::string hexvalStr =
          dumpHexData(*(const_cast<ByteDynArray*>(value.getValue())));
      const char* hexval = hexvalStr.c_str();
      char* szAux = new char[strlen(szoid) + strlen(hexval) + 5];
      snprintf(szAux, strlen(szoid) + strlen(hexval) + 5, "%s:%s", szoid,
               hexval);
      pSI->pszExtensions[j] = new char[strlen(szAux) + 1];
      snprintf(pSI->pszExtensions[j], MAX_LEN * 2, "%s", szAux);
      delete[] szAux;
    }

    cert.getExpiration().getUTCTime(pSI->szExpiration);
    cert.getFrom().getUTCTime(pSI->szValidFrom);

    ByteDynArray certificate;
    cert.toByteArray(certificate);

    pSI->nCertLen = certificate.size();
    pSI->pCertificate = new BYTE[pSI->nCertLen];
    memcpy(pSI->pCertificate, certificate.data(), pSI->nCertLen);

    snprintf(pSI->szSigningTime, MAX_LEN, "%s", "");

    try {
      CASN1UTCTime signingTime = si.getSigningTime();

      char szTime[MAX_LEN];
      signingTime.getUTCTime(szTime);
      snprintf(pSI->szSigningTime, MAX_LEN, "%s", szTime);

      pSI->b2011Error = (!(pSI->bitmask & VERIFIED_CERT_SHA256)) &&
                        (strncmp(szTime, "110630", 6) > 0);

    } catch (...) {
      snprintf(pSI->szSigningTime, MAX_LEN, "%s", "");
      pSI->b2011Error = false;
    }

    snprintf(pSI->szCertificateV2, MAX_LEN, "%s",
             szSHA256OID);  // default value

    int counterSignatureCount = si.getCountersignatureCount();
    if (counterSignatureCount > 0) {
      CASN1SetOf certificates = sd.getCertificates();
      verify_countersignature(pContext, si, certificates, pSI, pVerifyInfo);
    }

    if (si.hasTimeStampToken()) {
      LOG_DBG((0, "verify_signed_document 2", "Has TimeStamp"));

      CTimeStampToken tst = si.getTimeStampToken();

      TS_INFO* pTSInfo = new TS_INFO;

      CCertificate tsacert(tst.getCertificates().elementAt(0));

      ByteDynArray subject2;
      ByteDynArray issuer2;

      tsacert.getSubject().getNameAsString(subject2);
      tsacert.getIssuer().getNameAsString(issuer2);

      snprintf(pTSInfo->signerInfo.szDN, MAX_LEN * 2, "%s",
               reinterpret_cast<char*>(subject2.data()));
      snprintf(pTSInfo->signerInfo.szCADN, MAX_LEN * 2, "%s",
               reinterpret_cast<char*>(issuer2.data()));

      CTSTInfo tstInfo(tst.getTSTInfo());

      snprintf(pTSInfo->signerInfo.szSN, MAX_LEN * 2, "%s",
               dumpHexData(*(const_cast<ByteDynArray*>(
                               cert.getSerialNumber().getValue())))
                   .c_str());
      snprintf(pTSInfo->szTimeStampSerial, MAX_LEN, "%s",
               dumpHexData(*(const_cast<ByteDynArray*>(
                               tstInfo.getSerialNumber().getValue())))
                   .c_str());

      tstInfo.getUTCTime().getUTCTime(pTSInfo->szTimestamp);

      tsacert.getExpiration().getUTCTime(pTSInfo->signerInfo.szExpiration);
      tsacert.getFrom().getUTCTime(pTSInfo->signerInfo.szValidFrom);

      ByteDynArray certificate2;
      tsacert.toByteArray(certificate2);

      pTSInfo->signerInfo.nCertLen = certificate2.size();
      pTSInfo->signerInfo.pCertificate = new BYTE[pTSInfo->signerInfo.nCertLen];
      memcpy(pTSInfo->signerInfo.pCertificate, certificate2.data(),
             pTSInfo->signerInfo.nCertLen);

      pTSInfo->signerInfo.pRevocationInfo = nullptr;
      if (pContext->bVerifyCRL)
        pTSInfo->signerInfo.pRevocationInfo = new REVOCATION_INFO;

      pTSInfo->signerInfo.bitmask =
          tst.verify(pTSInfo->signerInfo.pRevocationInfo);

      // MessageImprint
      CASN1Sequence messageImprint = tstInfo.getMessageImprint();

      // algo
      CAlgorithmIdentifier algoid(messageImprint.elementAt(0));
      CASN1ObjectIdentifier timeStampImprintAlgorithm(algoid.elementAt(0));

      ByteDynArray oid1;
      timeStampImprintAlgorithm.ToOidString(oid1);
      snprintf(pTSInfo->szTimeStampImprintAlgorithm, MAX_LEN, "%s",
               reinterpret_cast<char*>(oid1.data()));

      // imprint b64
      CASN1OctetString mimprint(messageImprint.elementAt(1));
      const ByteDynArray* val = mimprint.getValue();

      ByteArray ba(const_cast<BYTE*>(val->data()), val->size());
      std::string b64Encoded;
      CBase64().Encode(ba, b64Encoded);

      snprintf(pTSInfo->szTimeStampMessageImprint, MAX_LEN, "%s",
               b64Encoded.c_str());

      // digest algo
      CASN1ObjectIdentifier digestOID2(
          tstInfo.getDigestAlgorithn().elementAt(0));
      ByteDynArray oid2;
      digestOID2.ToOidString(oid2);
      snprintf(pTSInfo->signerInfo.szDigestAlgorithm, MAX_LEN, "%s",
               reinterpret_cast<char*>(oid2.data()));
      pSI->pTimeStamp = pTSInfo;
    } else {
      LOG_DBG((0, "verify_signed_document 2", "Doesn't Have TimeStamp"));

      pSI->pTimeStamp = nullptr;
    }

    index++;
  }

  try {
    ByteDynArray content;
    sd.getContent(content);
    CSignedDocument sd1(content.data(), content.size());
    LOG_DBG((0, "<-- verify_signed_document 2", ""));
    return verify_signed_document(index, pContext, sd1, pVerifyInfo);
  } catch (...) {
    LOG_DBG((0, "verify_signed_document 2", "no embedded signature"));
  }

  LOG_MSG((0, "<-- verify_signed_document", "Context: %p", pContext));

  return 0;
}
#pragma GCC diagnostic pop

long verify_signed_document(CIE_VERIFY_CONTEXT* pContext, CSignedDocument& sd,
                            VERIFY_INFO* pVerifyInfo) {
  LOG_MSG((0, "--> verify_signed_document", "Context: %p", pContext));

  int signatureCount = getEmbeddedSignatureCount(sd);

  LOG_MSG((0, "verify_signed_document", "Signature Count: %d", signatureCount));

  pVerifyInfo->pSignerInfos = new SIGNER_INFOS;
  pVerifyInfo->pSignerInfos->nCount = signatureCount;  // = sd.getSignerCount();

  pVerifyInfo->pSignerInfos->pSignerInfo = new SIGNER_INFO[signatureCount];

  return verify_signed_document(0, pContext, sd, pVerifyInfo);
}

long sign_xml(CIE_SIGN_CONTEXT* pContext, const ByteDynArray& data) {
  LOG_MSG((0, "--> sign_xml", "Context: %p", pContext));

  CXAdESGenerator xadesGenerator(pContext->pSignatureGenerator);

  xadesGenerator.SetData(data);
  xadesGenerator.SetXAdES(pContext->pSignatureGenerator->GetCAdES());
  xadesGenerator.SetFileName(pContext->szInputFile);

  ByteDynArray xadesData;
  long nRes = xadesGenerator.Generate(xadesData, pContext->bDetached,
                                      pContext->bVerifyCert);
  if (nRes) {
    return nRes;
  }

  if (pContext->szOutputFile[0] == 0) {
    if (pContext->bDetached)
      snprintf(pContext->szOutputFile, sizeof(pContext->szOutputFile),
               "signed_%.1012s.xml", pContext->szInputFile);
    else
      snprintf(pContext->szOutputFile, sizeof(pContext->szOutputFile),
               "%.1019s.xml", pContext->szInputFile);
  }

  if (writeByteArrayToFile(pContext->szOutputFile, xadesData) != 0) {
    LOG_ERR((0, "<-- sign_xml",
             "Context: %p, Error: CIE_SIGN_ERROR_FILE_NOT_FOUND, file: %s",
             pContext, pContext->szOutputFile));
    return CIE_SIGN_ERROR_FILE_NOT_FOUND;
  }

  LOG_MSG((0, "<-- sign_xml", "Context: %p, RetVal: %x", pContext, nRes));

  return nRes;
}

long sign_pdf(CIE_SIGN_CONTEXT* pContext, const ByteDynArray& data) {
  LOG_MSG((0, "--> sign_pdf", "Context: %p", pContext));

  PdfSignatureGenerator sigGen;

  int nSigCount =
      sigGen.Load(reinterpret_cast<char*>(data.data()), data.size());

  LOG_DBG((0, "sign_pdf", "Context: %p, SigCount %d", pContext, nSigCount));

  std::string sigName = "Signature";
  sigName += ('1' + nSigCount);

  LOG_DBG((0, "sign_pdf",
           "Context: %p, InitSignature %d, %f, %f, %f, %f, %s, %s, %s, %s, %s, "
           "imageDataLen=%d",
           pContext, pContext->nPdfPage, pContext->fPdfLeft,
           pContext->fPdfBottom, pContext->fPdfWidth, pContext->fPdfHeight,
           pContext->szPdfReason, pContext->szPdfName, pContext->szPdfLocation,
           sigName.c_str(), pContext->szPdfSubfilter,
           pContext->nPdfImageDataLen));

  if (pContext->pPdfImageData != nullptr ||
      pContext->szPdfDescription[0] != 0 ||
      (pContext->fPdfLeft + pContext->fPdfBottom + pContext->fPdfWidth +
       pContext->fPdfHeight) != 0) {
    if (!pContext->szPdfReason[0]) {
      CCertificate* pCertificate;
      long r = pContext->pSignatureGenerator->GetCertificate(&pCertificate);
      if (r == 0) {
        std::string giveName =
            pCertificate->getSubject().getField(OID_GIVEN_NAME);
        std::string surname = pCertificate->getSubject().getField(OID_SURNAME);

        snprintf(pContext->szPdfReason, MAX_PATH, "%s %s", giveName.c_str(),
                 surname.c_str());

        time_t rawtime;
        const struct tm* timeinfo;
        char buffer[80];

        time(&rawtime);
        timeinfo = localtime(&rawtime);

        strftime(buffer, sizeof(buffer), "%d/%m/%Y %H:%M:%S", timeinfo);

        snprintf(pContext->szPdfName, MAX_PATH, "%s", buffer);

        pContext->szPdfReasonLabel[0] = 0;
        pContext->szPdfNameLabel[0] = 0;

        delete pCertificate;
      }
    }
    sigGen.InitSignature(
        pContext->nPdfPage, pContext->fPdfLeft, pContext->fPdfBottom,
        pContext->fPdfWidth, pContext->fPdfHeight, pContext->szPdfReason,
        pContext->szPdfReasonLabel, pContext->szPdfName,
        pContext->szPdfNameLabel, pContext->szPdfLocation,
        pContext->szPdfLocationLabel, sigName.c_str(), pContext->szPdfSubfilter,
        pContext->pPdfImageData, pContext->nPdfImageDataLen,
        pContext->szPdfDescription);
  } else {
    sigGen.InitSignature(0, pContext->szPdfReason, pContext->szPdfReasonLabel,
                         pContext->szPdfName, pContext->szPdfNameLabel,
                         pContext->szPdfLocation, pContext->szPdfLocationLabel,
                         sigName.c_str(), pContext->szPdfSubfilter);
  }

  LOG_DBG((0, "sign_pdf", "InitSignature OK"));

  pContext->pSignatureGenerator->SetHashAlgo(pContext->nHashAlgo);

  CIEPdfSigner signer(pContext);
  PdfMemDocument* document = sigGen.m_pPdfDocument.get();
  BufferStreamDevice* device = sigGen.m_pSignOutputDevice.get();
  PdfSignature* signature = sigGen.m_pSignatureField;

  PoDoFo::SignDocument(*document, *device, signer, *signature);

  ByteDynArray signedPdf;
  sigGen.GetSignedPdf(signedPdf);

  LOG_DBG((0, "sign_pdf", "Get Signed PDF OK"));

  if (pContext->szOutputFile[0] == 0) {
    snprintf(pContext->szOutputFile, sizeof(pContext->szOutputFile),
             "%.1019s.pdf", pContext->szInputFile);
  }

  LOG_DBG((0, "sign_pdf", "OutFile: %s", pContext->szOutputFile));

  if (writeByteArrayToFile(pContext->szOutputFile, signedPdf) != 0) {
    LOG_ERR((0, "<-- sign_pdf",
             "Context: %p, Error: CIE_SIGN_ERROR_FILE_NOT_FOUND, file: %s",
             pContext, pContext->szOutputFile));
    return CIE_SIGN_ERROR_FILE_NOT_FOUND;
  }

  LOG_MSG((0, "<-- sign_pdf", "Context: %p", pContext));

  return 0;
}

long verify_pdf(CIE_VERIFY_CONTEXT* pContext, ByteDynArray& /*data*/,
                VERIFY_INFO* pVerifyInfo) {
  PDFVerifier pdfVerifier;

  // Use file-path Load() to avoid PoDoFo buffer-parsing issues with
  // xref-stream PDFs that were signed with an incremental xref table update.
  long nRes = pdfVerifier.Load(pContext->szInputFile);

  if (nRes) {
    LOG_ERR((0, "<-- verify_pdf", "Context: %p, Error: %x", pContext, nRes));
    return nRes;
  }

  int signatureCount = pdfVerifier.GetNumberOfSignatures();

  pVerifyInfo->pSignerInfos = new SIGNER_INFOS;
  pVerifyInfo->pSignerInfos->nCount = signatureCount;
  pVerifyInfo->pSignerInfos->pSignerInfo = new SIGNER_INFO[signatureCount];

  for (int i = 0; i < signatureCount; i++) {
    ByteDynArray sig;

#ifndef HP_UX
    SignatureAppearanceInfo sai;
    nRes = pdfVerifier.GetSignature(i, sig, sai);
#else
    nRes = pdfVerifier.GetSignature(i, sig);  //, sai);
#endif

    if (nRes) {
      freeSignerInfos(pVerifyInfo->pSignerInfos, i);
      pVerifyInfo->pSignerInfos = nullptr;
      LOG_ERR((0, "<-- verify_pdf", "Context: %p, Error: %x", pContext, nRes));
      return nRes;
    }

    CSignedDocument sd(sig.data(), sig.size());

    CCertificate cert = sd.getSignerCertificate(0);
    CSignerInfo si = sd.getSignerInfo(0);

    SIGNER_INFO* pSI = &(pVerifyInfo->pSignerInfos->pSignerInfo[i]);  // = pSI;
    pSI->pCounterSignatures = nullptr;
    pSI->nCounterSignatureCount = 0;
    pSI->pRevocationInfo = nullptr;
    if (pContext->bVerifyCRL) pSI->pRevocationInfo = new REVOCATION_INFO;

    char sigType[256];
    pSI->bitmask =
        pdfVerifier.VerifySignature(i, nullptr, sigType, pSI->pRevocationInfo);

    ByteDynArray subject;
    ByteDynArray issuer;
    cert.getSubject().getNameAsString(subject);
    cert.getIssuer().getNameAsString(issuer);

    std::string giveName = cert.getSubject().getField(OID_GIVEN_NAME);
    std::string surname = cert.getSubject().getField(OID_SURNAME);
    std::string commonName = cert.getSubject().getField(OID_COMMON_NAME);

    snprintf(pSI->szCN, MAX_LEN * 2, "%s", commonName.c_str());
    snprintf(pSI->szGIVENNAME, MAX_LEN * 2, "%s", giveName.c_str());
    snprintf(pSI->szSURNAME, MAX_LEN * 2, "%s", surname.c_str());

    snprintf(pSI->szDN, MAX_LEN * 2, "%s",
             reinterpret_cast<char*>(subject.data()));
    snprintf(pSI->szCADN, MAX_LEN * 2, "%s",
             reinterpret_cast<char*>(issuer.data()));

    snprintf(pSI->szSN, MAX_LEN * 2, "%s",
             dumpHexData(*(const_cast<ByteDynArray*>(
                             cert.getSerialNumber().getValue())))
                 .c_str());

    try {
      CASN1UTCTime signingTime = si.getSigningTime();

      char szTime[MAX_LEN];
      signingTime.getUTCTime(szTime);
      snprintf(pSI->szSigningTime, MAX_LEN, "%s", szTime);

      pSI->b2011Error = (!(pSI->bitmask & VERIFIED_CERT_SHA256)) &&
                        (strncmp(szTime, "110630", 6) > 0);

    } catch (...) {
      snprintf(pSI->szSigningTime, MAX_LEN, "%s", "");
      pSI->b2011Error = false;
    }

    CASN1ObjectIdentifier digestOID(si.getDigestAlgorithn().elementAt(0));

    ByteDynArray oid;
    digestOID.ToOidString(oid);
    snprintf(pSI->szDigestAlgorithm, MAX_LEN, "%s",
             reinterpret_cast<char*>(oid.data()));

    CASN1Sequence certExtensions(cert.getExtensions());
    CASN1Sequence extensions(certExtensions.elementAt(0));
    int count = extensions.size();
    pSI->nExtensionsCount = count;
    pSI->pszExtensions = new char*[count];
    for (int j = 0; j < count; j++) {
      CASN1Sequence extension(extensions.elementAt(j));
      CASN1ObjectIdentifier extoid(extension.elementAt(0));
      CASN1OctetString value(extension.elementAt(1));

      ByteDynArray oidName;
      extoid.ToOidString(oidName);
      const char* szoid =
          g_mapOIDProps.getProperty(reinterpret_cast<char*>(oidName.data()),
                                    reinterpret_cast<char*>(oidName.data()));
      std::string hexvalStr =
          dumpHexData(*(const_cast<ByteDynArray*>(value.getValue())));
      const char* hexval = hexvalStr.c_str();
      char* szAux = new char[strlen(szoid) + strlen(hexval) + 5];
      snprintf(szAux, strlen(szoid) + strlen(hexval) + 5, "%s:%s", szoid,
               hexval);
      pSI->pszExtensions[j] = new char[strlen(szAux) + 1];
      snprintf(pSI->pszExtensions[j], MAX_LEN * 2, "%s", szAux);
      delete[] szAux;
    }

    cert.getExpiration().getUTCTime(pSI->szExpiration);
    cert.getFrom().getUTCTime(pSI->szValidFrom);

    ByteDynArray certificate;
    cert.toByteArray(certificate);

    pSI->nCertLen = certificate.size();
    pSI->pCertificate = new BYTE[pSI->nCertLen];
    memcpy(pSI->pCertificate, certificate.data(), pSI->nCertLen);

    if (si.hasTimeStampToken()) {
      CTimeStampToken tst = si.getTimeStampToken();

      TS_INFO* pTSInfo = new TS_INFO;

      CCertificate tsacert(tst.getCertificates().elementAt(0));

      ByteDynArray subject2;
      ByteDynArray issuer2;

      tsacert.getSubject().getNameAsString(subject2);
      tsacert.getIssuer().getNameAsString(issuer2);

      snprintf(pTSInfo->signerInfo.szDN, MAX_LEN * 2, "%s",
               reinterpret_cast<char*>(subject2.data()));
      snprintf(pTSInfo->signerInfo.szCADN, MAX_LEN * 2, "%s",
               reinterpret_cast<char*>(issuer2.data()));

      CTSTInfo tstInfo(tst.getTSTInfo());

      CASN1ObjectIdentifier digestOID2(
          tstInfo.getDigestAlgorithn().elementAt(0));
      ByteDynArray oid2;
      digestOID2.ToOidString(oid2);
      snprintf(pTSInfo->signerInfo.szDigestAlgorithm, MAX_LEN, "%s",
               reinterpret_cast<char*>(oid2.data()));

      snprintf(pTSInfo->signerInfo.szSN, MAX_LEN * 2, "%s",
               dumpHexData(*(const_cast<ByteDynArray*>(
                               tstInfo.getSerialNumber().getValue())))
                   .c_str());

      tstInfo.getUTCTime().getUTCTime(pTSInfo->szTimestamp);

      tsacert.getExpiration().getUTCTime(pTSInfo->signerInfo.szExpiration);
      tsacert.getFrom().getUTCTime(pTSInfo->signerInfo.szValidFrom);

      ByteDynArray certificate2;
      tsacert.toByteArray(certificate2);

      pTSInfo->signerInfo.nCertLen = certificate2.size();
      pTSInfo->signerInfo.pCertificate = new BYTE[pTSInfo->signerInfo.nCertLen];
      memcpy(pTSInfo->signerInfo.pCertificate, certificate2.data(),
             pTSInfo->signerInfo.nCertLen);

      pTSInfo->signerInfo.pRevocationInfo = nullptr;
      if (pContext->bVerifyCRL)
        pTSInfo->signerInfo.pRevocationInfo = new REVOCATION_INFO;

      pTSInfo->signerInfo.bitmask =
          tst.verify(pTSInfo->signerInfo.pRevocationInfo);

      pSI->pTimeStamp = pTSInfo;
    } else {
      pSI->pTimeStamp = nullptr;
    }
  }

  LOG_MSG((0, "<-- verify_pdf", "Context: %p", pContext));

  return 0;
}

long verify_pdf(CIE_VERIFY_CONTEXT* pContext, VERIFY_INFO* pVerifyInfo) {
  LOG_MSG((0, "--> verify_pdf", "Context: %p", pContext));

  ByteDynArray data;
  if (readFileIntoByteArray(pContext->szInputFile, data) != 0) {
    LOG_ERR((0, "<-- verify_pdf",
             "Context: %p, Error: CIE_SIGN_ERROR_FILE_NOT_FOUND, file: %s",
             pContext, pContext->szInputFile));
    return CIE_SIGN_ERROR_FILE_NOT_FOUND;
  }

  return verify_pdf(pContext, data, pVerifyInfo);
}

long verify_tsd(CIE_VERIFY_CONTEXT* pContext, VERIFY_INFO* pVerifyInfo) {
  LOG_MSG((0, "--> verify_tsd", "Context: %p", pContext));

  ByteDynArray data;
  if (readFileIntoByteArray(pContext->szInputFile, data) != 0) {
    LOG_ERR((0, "<-- verify_tsd",
             "Context: %p, Error: CIE_SIGN_ERROR_FILE_NOT_FOUND, file: %s",
             pContext, pContext->szInputFile));
    return CIE_SIGN_ERROR_FILE_NOT_FOUND;
  }

  BYTE* pbContent;
  int len = data.size();
  ByteDynArray decoded;
  if (data.data()[0] != 0x30) {
    // base64
    std::string encoded(reinterpret_cast<const char*>(data.data()),
                        static_cast<size_t>(len));

    // strip PEM header/footer if present
    auto dash = encoded.find("--");
    if (dash != std::string::npos) {
      auto start = encoded.find('\n', dash);
      auto end = encoded.rfind("\n--");
      if (start != std::string::npos)
        encoded = encoded.substr(start + 1, end != std::string::npos
                                                ? end - (start + 1)
                                                : std::string::npos);
    }

    encoded.erase(std::remove_if(encoded.begin(), encoded.end(),
                                 [](char c) { return c == '\r' || c == '\n'; }),
                  encoded.end());

    CBase64().Decode(encoded.c_str(), decoded);

    pbContent = decoded.data();
    len = decoded.size();
  } else {
    pbContent = const_cast<BYTE*>(data.data());
    len = data.size();
  }

  BufferedReader reader(pbContent, len);
  CTimeStampData tsd(reader);
  CTimeStampToken tst(tsd.getTimeStampToken());

  CASN1OctetString octetString(tsd.getTimeStampDataContent());
  ByteDynArray content;
  if (octetString.getTag() == 0x24) {  // contructed octet string
    CASN1Sequence contentArray(octetString);
    int size = contentArray.size();
    for (int i = 0; i < size; i++) {
      content.append(ByteArray(contentArray.elementAt(i).getValue()->data(),
                               contentArray.elementAt(i).getLength()));
    }
  } else {
    content.append(
        ByteArray(octetString.getValue()->data(), octetString.getLength()));
  }

  try {
    CSignedDocument sd(content.data(), content.size());

    long nRet = verify_signed_document(pContext, sd, pVerifyInfo);
    if (nRet) return nRet;

    LOG_DBG((0, "verify_tsd", "Signature Count: %d",
             pVerifyInfo->pSignerInfos->nCount));

  } catch (...) {
  }

  pVerifyInfo->pTSInfo = new TS_INFO;

  return verifyTST(tst, pVerifyInfo->pTSInfo, pContext->bVerifyCRL);
}

long verify_tst(CIE_VERIFY_CONTEXT* pContext, VERIFY_INFO* pVerifyInfo) {
  LOG_MSG((0, "--> verify_tst", "Context: %p", pContext));

  ByteDynArray data;
  if (readFileIntoByteArray(pContext->szInputFile, data) != 0) {
    LOG_ERR((0, "<-- verify_tst",
             "Context: %p, Error: CIE_SIGN_ERROR_FILE_NOT_FOUND, file: %s",
             pContext, pContext->szInputFile));
    return CIE_SIGN_ERROR_FILE_NOT_FOUND;
  }

  pVerifyInfo->pTSInfo = new TS_INFO;

  BufferedReader reader(data);
  CTimeStampToken tst(reader);

  return verifyTST(tst, pVerifyInfo->pTSInfo, pContext->bVerifyCRL);
}

long verify_tsr(CIE_VERIFY_CONTEXT* pContext, VERIFY_INFO* pVerifyInfo) {
  LOG_MSG((0, "--> verify_tsr", "Context: %p", pContext));

  ByteDynArray data;
  if (readFileIntoByteArray(pContext->szInputFile, data) != 0) {
    LOG_ERR((0, "<-- verify_tsr",
             "Context: %p, Error: CIE_SIGN_ERROR_FILE_NOT_FOUND, file: %s",
             pContext, pContext->szInputFile));
    return CIE_SIGN_ERROR_FILE_NOT_FOUND;
  }

  pVerifyInfo->pTSInfo = new TS_INFO;

  BYTE* pbContent;
  int len = data.size();
  ByteDynArray decoded;
  if (data.data()[0] != 0x30) {
    // base64
    std::string encoded(reinterpret_cast<const char*>(data.data()),
                        static_cast<size_t>(len));

    // strip PEM header/footer if present
    auto dash = encoded.find("--");
    if (dash != std::string::npos) {
      auto start = encoded.find('\n', dash);
      auto end = encoded.rfind("\n--");
      if (start != std::string::npos)
        encoded = encoded.substr(start + 1, end != std::string::npos
                                                ? end - (start + 1)
                                                : std::string::npos);
    }

    encoded.erase(std::remove_if(encoded.begin(), encoded.end(),
                                 [](char c) { return c == '\r' || c == '\n'; }),
                  encoded.end());

    CBase64().Decode(encoded.c_str(), decoded);

    pbContent = decoded.data();
    len = decoded.size();
  } else {
    pbContent = const_cast<BYTE*>(data.data());
    len = data.size();
  }

  CTimeStampResponse tsr(pbContent, len);
  CTimeStampToken tst(tsr.getTimeStampToken());

  return verifyTST(tst, pVerifyInfo->pTSInfo, pContext->bVerifyCRL);
}

long verifyTST(CTimeStampToken& tst, TS_INFO* pTSInfo, BOOL bVerifyCRL) {
  LOG_MSG((0, "--> verifyTST", "TS_INFO: %p", pTSInfo));

  pTSInfo->signerInfo.pCounterSignatures = nullptr;
  pTSInfo->signerInfo.nCounterSignatureCount = 0;
  pTSInfo->signerInfo.szCertificateV2[0] = 0;

  CCertificate tsacert(tst.getCertificates().elementAt(0));

  tsacert.getExpiration().getUTCTime(pTSInfo->signerInfo.szExpiration);
  tsacert.getFrom().getUTCTime(pTSInfo->signerInfo.szValidFrom);

  ByteDynArray subject;
  ByteDynArray issuer;

  tsacert.getSubject().getNameAsString(subject);
  tsacert.getIssuer().getNameAsString(issuer);

  snprintf(pTSInfo->signerInfo.szDN, MAX_LEN * 2, "%s",
           reinterpret_cast<char*>(subject.data()));
  snprintf(pTSInfo->signerInfo.szCADN, MAX_LEN * 2, "%s",
           reinterpret_cast<char*>(issuer.data()));

  CTSTInfo tstInfo(tst.getTSTInfo());
  tstInfo.getUTCTime().getUTCTime(pTSInfo->szTimestamp);

  snprintf(pTSInfo->signerInfo.szSN, MAX_LEN * 2, "%s",
           dumpHexData(*(const_cast<ByteDynArray*>(
                           tsacert.getSerialNumber().getValue())))
               .c_str());
  snprintf(pTSInfo->szTimeStampSerial, MAX_LEN, "%s",
           dumpHexData(*(const_cast<ByteDynArray*>(
                           tstInfo.getSerialNumber().getValue())))
               .c_str());

  tsacert.getExpiration().getUTCTime(pTSInfo->signerInfo.szExpiration);
  tsacert.getFrom().getUTCTime(pTSInfo->signerInfo.szValidFrom);

  const ByteDynArray* certificate =
      const_cast<ByteDynArray*>(tsacert.getValue());

  pTSInfo->signerInfo.nCertLen = certificate->size();
  pTSInfo->signerInfo.pCertificate = new BYTE[pTSInfo->signerInfo.nCertLen];
  memcpy(pTSInfo->signerInfo.pCertificate, certificate->data(),
         pTSInfo->signerInfo.nCertLen);

  pTSInfo->signerInfo.pRevocationInfo = nullptr;

  if (bVerifyCRL) pTSInfo->signerInfo.pRevocationInfo = new REVOCATION_INFO;

  pTSInfo->signerInfo.bitmask = tst.verify(pTSInfo->signerInfo.pRevocationInfo);

  // MessageImprint
  CASN1Sequence messageImprint = tstInfo.getMessageImprint();

  // algo
  CAlgorithmIdentifier algoid(messageImprint.elementAt(0));
  CASN1ObjectIdentifier timeStampImprintAlgorithm(algoid.elementAt(0));
  ByteDynArray oid1;
  timeStampImprintAlgorithm.ToOidString(oid1);
  snprintf(pTSInfo->szTimeStampImprintAlgorithm, MAX_LEN, "%s",
           reinterpret_cast<char*>(oid1.data()));

  // imprint b64
  CASN1OctetString mimprint(messageImprint.elementAt(1));
  const ByteDynArray* val = mimprint.getValue();

  ByteArray ba(const_cast<BYTE*>(val->data()), val->size());
  std::string b64Encoded;
  CBase64().Encode(ba, b64Encoded);

  snprintf(pTSInfo->szTimeStampMessageImprint, MAX_LEN, "%s",
           b64Encoded.c_str());

  CASN1ObjectIdentifier digestOID(tstInfo.getDigestAlgorithn().elementAt(0));
  ByteDynArray oid;
  digestOID.ToOidString(oid);
  snprintf(pTSInfo->signerInfo.szDigestAlgorithm, MAX_LEN, "%s",
           reinterpret_cast<char*>(oid.data()));

  pTSInfo->signerInfo.nExtensionsCount = 0;

  LOG_MSG((0, "<-- verifyTST", "TS_INFO: %p", pTSInfo));

  return 0;
}

int get_file_type(const char* szFileName) {
  const char* pos = strrchr(szFileName, '.');
  if (pos) {
    const char* szExt = pos;
    if (STRICMP(szExt, ".p7m") == 0)
      return CIE_SIGN_FILETYPE_P7M;
    else if (STRICMP(szExt, ".m7m") == 0)
      return CIE_SIGN_FILETYPE_M7M;
    else if (STRICMP(szExt, ".pdf") == 0)
      return CIE_SIGN_FILETYPE_PDF;
    else if (STRICMP(szExt, ".tsr") == 0)
      return CIE_SIGN_FILETYPE_TSR;
    else if (STRICMP(szExt, ".tsd") == 0)
      return CIE_SIGN_FILETYPE_TSD;
    else if (STRICMP(szExt, ".xml") == 0)
      return CIE_SIGN_FILETYPE_XML;
    else if (STRICMP(szExt, ".tst") == 0)
      return CIE_SIGN_FILETYPE_TST;
    else
      return CIE_SIGN_FILETYPE_PLAINTEXT;
  }

  return CIE_SIGN_FILETYPE_PLAINTEXT;
}

void CIEPdfSigner::ComputeSignature(charbuff& buffer, bool dryrun) {
  if (dryrun) {
    buffer.resize(SIGNATURE_SIZE * 2);
  } else {
    long nRes;
    ByteDynArray toSign(
        ByteArray(reinterpret_cast<BYTE*>(m_buffer.data()), m_buffer.size()));
    ByteDynArray signedData;

    m_pContext->pSignatureGenerator->SetData(toSign);
    nRes = m_pContext->pSignatureGenerator->Generate(signedData, true,
                                                     m_pContext->bVerifyCert);
    if (nRes) {
      LOG_ERR((0, "CIEPdfSigner::ComputeSignature", "Generate NOK: %x", nRes));
    }

    buffer.resize(signedData.size());
    std::memcpy(buffer.data(), reinterpret_cast<char*>(signedData.data()),
                signedData.size());
  }
}
