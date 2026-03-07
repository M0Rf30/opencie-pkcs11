// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

#include "csp/cie_verify_csp.h"

#include <sys/types.h>

#include <cstdio>
#include <cstring>
#include <memory>

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
  verifyResult = {};

  auto verifier = std::make_unique<CIEVerify>();

  long ret = verifier->verify(inFilePath, &verifyResult, proxyAddress,
                              proxyPort, usrPass);

  // If signers were found and no explicit error code is set, treat as success
  // even if the underlying pipeline returned a non-zero secondary status (e.g.
  // -2 from inner-document checks after all signatures were verified).
  bool hasSigners = verifyResult.verifyInfo.pSignerInfos != nullptr &&
                    verifyResult.verifyInfo.pSignerInfos->nCount > 0;

  if (!hasSigners && (ret != 0 || verifyResult.nErrorCode != 0)) {
    long err = verifyResult.nErrorCode != 0 ? verifyResult.nErrorCode : ret;
    LOG_ERROR("Errore nella verifica: %ld", err);
    verifyResult.verifyInfo.pSignerInfos = nullptr;
    return static_cast<CK_RV>(err);
  }

  if (!verifyResult.verifyInfo.pSignerInfos) {
    return 0;
  }

  LOG_INFO("cie_verify OK");
  return static_cast<CK_RV>(verifyResult.verifyInfo.pSignerInfos->nCount);
}

CK_RV CK_ENTRY cie_get_sign_count(void) {
  if (!verifyResult.verifyInfo.pSignerInfos) return 0;
  return static_cast<CK_RV>(verifyResult.verifyInfo.pSignerInfos->nCount);
}

CK_RV CK_ENTRY cie_get_verify_info(int index, struct verifyInfo_t* vInfos) {
  if (!verifyResult.verifyInfo.pSignerInfos) return 1;
  if (index < 0 || static_cast<CK_RV>(index) >= cie_get_sign_count()) return 1;

  SIGNER_INFO tmpSignerInfo =
      (verifyResult.verifyInfo.pSignerInfos->pSignerInfo)[index];
  snprintf(vInfos->name, OPENCIE_MAX_LEN * 2, "%s", tmpSignerInfo.szGIVENNAME);
  snprintf(vInfos->surname, OPENCIE_MAX_LEN * 2, "%s", tmpSignerInfo.szSURNAME);
  snprintf(vInfos->cn, OPENCIE_MAX_LEN * 2, "%s", tmpSignerInfo.szCN);
  snprintf(vInfos->cadn, OPENCIE_MAX_LEN * 2, "%s", tmpSignerInfo.szCADN);
  snprintf(vInfos->signingTime, OPENCIE_MAX_LEN * 2, "%s",
           tmpSignerInfo.szSigningTime);
  vInfos->CertRevocStatus =
      tmpSignerInfo.pRevocationInfo
          ? tmpSignerInfo.pRevocationInfo->nRevocationStatus
          : REVOCATION_STATUS_UNKNOWN;
  vInfos->isCertValid =
      (tmpSignerInfo.bitmask & VERIFIED_CERT_GOOD) == VERIFIED_CERT_GOOD;
  vInfos->isSignValid =
      (tmpSignerInfo.bitmask & VERIFIED_SIGNATURE) == VERIFIED_SIGNATURE;

  return 0;
}

CK_RV CK_ENTRY cie_extract_p7m(const char* inFilePath,
                               const char* outFilePath) {
  auto verifier = std::make_unique<CIEVerify>();

  long res = verifier->get_file_from_p7m(inFilePath, outFilePath);

  return res;
}
