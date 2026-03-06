// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

#include "csp/cie_verify_csp.h"

#include <memory>

#include <sys/types.h>

#include "pkcs11/pkcs11_functions.h"

using namespace CieIDLogger;

VERIFY_RESULT verifyResult;

extern "C" {
CK_RV CK_ENTRY cie_verify(const char* inFilePath, const char* proxyAddress,
                              int proxyPort, const char* usrPass);
CK_RV CK_ENTRY cie_get_sign_count(void);
CK_RV CK_ENTRY cie_get_verify_info(int index, struct verifyInfo_t* vInfos);
CK_RV CK_ENTRY cie_extract_p7m(const char* inFilePath, const char* outFilePath);
}

CK_RV CK_ENTRY cie_verify(const char* inFilePath, const char* proxyAddress,
                              int proxyPort, const char* usrPass) {
  auto verifier = std::make_unique<CIEVerify>();

  verifier->verify(inFilePath, &verifyResult, proxyAddress,
                   proxyPort, usrPass);

  if (verifyResult.nErrorCode == 0) {
    LOG_INFO("cie_verify OK");
    return static_cast<CK_RV>(verifyResult.verifyInfo.pSignerInfos->nCount);
  } else {
    LOG_ERROR("Errore nella verifica: %lu", verifyResult.nErrorCode);
    return verifyResult.nErrorCode;
  }
}

CK_RV CK_ENTRY cie_get_sign_count(void) {
  return static_cast<CK_RV>(verifyResult.verifyInfo.pSignerInfos->nCount);
}

CK_RV CK_ENTRY cie_get_verify_info(int index, struct verifyInfo_t* vInfos) {
  if (index >= 0 && static_cast<CK_RV>(index) < cie_get_sign_count()) {
    SIGNER_INFO tmpSignerInfo =
        (verifyResult.verifyInfo.pSignerInfos->pSignerInfo)[index];
    snprintf(vInfos->name, MAX_LEN * 2, "%s", tmpSignerInfo.szGIVENNAME);
    snprintf(vInfos->surname, MAX_LEN * 2, "%s", tmpSignerInfo.szSURNAME);
    snprintf(vInfos->cn, MAX_LEN * 2, "%s", tmpSignerInfo.szCN);
    snprintf(vInfos->cadn, MAX_LEN * 2, "%s", tmpSignerInfo.szCADN);
    snprintf(vInfos->signingTime, MAX_LEN * 2, "%s", tmpSignerInfo.szSigningTime);
    vInfos->CertRevocStatus = tmpSignerInfo.pRevocationInfo->nRevocationStatus;
    vInfos->isCertValid =
        (tmpSignerInfo.bitmask & VERIFIED_CERT_GOOD) == VERIFIED_CERT_GOOD;
    vInfos->isSignValid =
        (tmpSignerInfo.bitmask & VERIFIED_SIGNATURE) == VERIFIED_SIGNATURE;
  }

  return 0;
}

CK_RV CK_ENTRY cie_extract_p7m(const char* inFilePath, const char* outFilePath) {
  auto verifier = std::make_unique<CIEVerify>();

  long res = verifier->get_file_from_p7m(inFilePath, outFilePath);

  return res;
}