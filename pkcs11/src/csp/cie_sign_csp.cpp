// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

#include "csp/cie_sign_csp.h"

#include "csp/cie_enable.h"
#include "csp/ias.h"
#include "logger/logger.h"
#include "pcsc/pcsc.h"
#include "pkcs11/pkcs11_functions.h"
#include "sign/cie_sign.h"
#include "Util/module_info.h"
#include "Util/util_exception.h"
#include "pcsc/pcsc_transport.h"

using namespace CieIDLogger;

#define CARD_PAN_MISMATCH (int)(0x000000F1)

extern "C" {
CK_RV CK_ENTRY cie_sign(const char* inFilePath, const char* type,
                           const char* pin, const char* pan, int page, float x,
                           float y, float w, float h, const char* imagePathFile,
                           const char* outFilePath,
                           PROGRESS_CALLBACK progressCallBack,
                           SIGN_COMPLETED_CALLBACK completedCallBack);
}

CK_RV CK_ENTRY cie_sign(const char* inFilePath, const char* type,
                           const char* pin, const char* pan, int page, float x,
                           float y, float w, float h, const char* imagePathFile,
                           const char* outFilePath,
                           PROGRESS_CALLBACK progressCallBack,
                           SIGN_COMPLETED_CALLBACK completedCallBack) {
  LOG_INFO("****** Starting cie_sign ******");
  LOG_DEBUG("cie_sign - page: %d, x: %f, y: %f, w: %f, h: %f", page, x, y, w,
            h);

  char* readers = nullptr;
  char* ATR = nullptr;
  bool panMismatch = false;
  try {
    std::map<uint8_t, ByteDynArray> hashSet;

    DWORD len = 0;
    ByteDynArray CertCIE;
    ByteDynArray SOD;

    SCARDCONTEXT hSC;

    auto transport = std::make_shared<PCSCTransport>();
    long nRet = transport->EstablishContext(SCARD_SCOPE_USER, &hSC);
    if (nRet != SCARD_S_SUCCESS) {
      LOG_ERROR("cie_sign - List readers error: %d\n", nRet);
      return CKR_DEVICE_ERROR;
    }
    LOG_INFO("cie_sign - Establish Context ok\n");

    nRet = transport->ListReaders(hSC, nullptr, &len);
    if (nRet != SCARD_S_SUCCESS) {
      LOG_ERROR("cie_sign - List readers error: %d\n", nRet);
      return CKR_TOKEN_NOT_PRESENT;
    }

    if (len == 1) return CKR_TOKEN_NOT_PRESENT;

    readers = static_cast<char*>(malloc(len));

    if (transport->ListReaders(hSC, readers, &len) !=
        SCARD_S_SUCCESS) {
      free(readers);
      return CKR_TOKEN_NOT_PRESENT;
    }

    char* curreader = readers;
    bool foundCIE = false;

    progressCallBack(25, "Looking for CIE...");

    for (; curreader[0] != 0; curreader += strnlen(curreader, len) + 1) {
      safeConnection conn(*transport, hSC, curreader, SCARD_SHARE_SHARED);
      if (!conn.hCard) continue;

      DWORD atrLen = 40;
      if (transport->GetAttrib(conn.hCard, SCARD_ATTR_ATR_STRING, reinterpret_cast<uint8_t*>(ATR),
                         &atrLen) != SCARD_S_SUCCESS) {
        free(readers);
        return CKR_DEVICE_ERROR;
      }

      ATR = static_cast<char*>(malloc(atrLen));

      if (transport->GetAttrib(conn.hCard, SCARD_ATTR_ATR_STRING, reinterpret_cast<uint8_t*>(ATR),
                         &atrLen) != SCARD_S_SUCCESS) {
        free(readers);
        free(ATR);
        return CKR_DEVICE_ERROR;
      }

      ByteArray atrBa(reinterpret_cast<BYTE*>(ATR), atrLen);

      IAS* ias = static_cast<IAS*>(malloc(sizeof(IAS)));
      new (ias)
          IAS(TokenTransmitCallback, atrBa);
      ias->SetCardContext(&conn);

      ias->token.Reset();
      // Continue looking for a CIE if the token is unrecognised
      try {
        ias->SelectAID_IAS();
      } catch (logged_error& err) {
        free(ATR);
        ATR = nullptr;
        free(ias);
        continue;
      }
      ias->ReadPAN();

      if (!foundCIE) foundCIE = true;
      ByteDynArray IntAuth;
      ias->SelectAID_CIE();
      ias->ReadDappPubKey(IntAuth);
      ias->SelectAID_CIE();
      ias->InitEncKey();

      ByteDynArray IdServizi;
      ias->ReadIdServizi(IdServizi);
      ByteArray baPan = ByteArray(reinterpret_cast<const uint8_t*>(pan), strlen(pan));

      // Check for pan mismatch and continue search in such case
      if (memcmp(baPan.data(), IdServizi.data(), IdServizi.size()) != 0) {
        panMismatch = true;
        free(ATR);
        ATR = nullptr;
        free(ias);
        continue;
      }

      progressCallBack(50, "Getting certificate from CIE...");

      ByteDynArray FullPIN;
      ByteArray LastPIN = ByteArray(reinterpret_cast<const uint8_t*>(pin), strlen(pin));
      ias->GetFirstPIN(FullPIN);
      FullPIN.append(LastPIN);
      ias->token.Reset();

      progressCallBack(75, "Starting signature...");

      char fullPinCStr[9];
      memcpy(fullPinCStr, FullPIN.data(), 8);
      fullPinCStr[8] = 0;

      CIESign* cieSign = static_cast<CIESign*>(malloc(sizeof(CIESign)));
      new (cieSign) CIESign(ias);

      uint16_t ret = cieSign->sign(inFilePath, type, fullPinCStr, page, x, y, w,
                                   h, imagePathFile, outFilePath);
      if ((ret & (0x63C0)) == 0x63C0) {
        free(readers);
        free(ATR);
        free(ias);
        free(cieSign);
        return CKR_PIN_INCORRECT;
      } else if (ret == 0x6983) {
        free(readers);
        free(ATR);
        free(ias);
        free(cieSign);
        return CKR_PIN_LOCKED;
      }

      progressCallBack(100, "OK!");

      LOG_INFO("cie_sign - completed, res: %d", ret);

      free(ias);
      free(cieSign);

      // At this point if there has been a pan mismatch doesn't matter
      if (panMismatch) panMismatch = false;

      completedCallBack(ret);

      // A this point a CIE has been found, stop looking for it
      break;
    }

    if (!foundCIE) {
      free(ATR);
      free(readers);
      return CKR_TOKEN_NOT_RECOGNIZED;
    }
  } catch (std::exception& ex) {
    LOG_ERROR(ex.what());
    if (ATR) free(ATR);
    LOG_ERROR("cie_sign - Exception: %s", ex.what());
    if (readers) free(readers);

    LOG_ERROR("cie_sign - General error\n");
    return CKR_GENERAL_ERROR;
  }

  if (ATR) free(ATR);

  free(readers);

  if (panMismatch) return CARD_PAN_MISMATCH;

  return SCARD_S_SUCCESS;
}
