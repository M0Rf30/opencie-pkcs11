// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "csp/cie_sign_csp.h"

#include <openssl/crypto.h>

#include <memory>

#include "csp/cie_enable.h"
#include "csp/ias.h"
#include "logger/logger.h"
#include "pcsc/pcsc.h"
#if defined(__ANDROID__)
#include "pcsc/android_nfc_transport.h"
#else
#include "pcsc/pcsc_transport.h"
#endif
#include "pkcs11/pkcs11_functions.h"
#include "sign/cie_sign.h"
#include "util/module_info.h"
#include "util/util_exception.h"

using namespace CieIDLogger;

#define CARD_PAN_MISMATCH (int)(0x000000F1)

extern "C" {
CK_RV CK_ENTRY cie_sign(const char* inFilePath, const char* type,
                        const char* pin, const char* pan, int page, float x,
                        float y, float w, float h,
                        const unsigned char* imageData, int imageDataLen,
                        const char* outFilePath,
                        PROGRESS_CALLBACK progressCallBack,
                        SIGN_COMPLETED_CALLBACK completedCallBack);
}

CK_RV CK_ENTRY cie_sign(const char* inFilePath, const char* type,
                        const char* pin, const char* pan, int page, float x,
                        float y, float w, float h,
                        const unsigned char* imageData, int imageDataLen,
                        const char* outFilePath,
                        PROGRESS_CALLBACK progressCallBack,
                        SIGN_COMPLETED_CALLBACK completedCallBack) {
  LOG_INFO("****** Starting cie_sign ******");
  LOG_DEBUG("cie_sign - page: %d, x: %f, y: %f, w: %f, h: %f", page, x, y, w,
            h);

  std::unique_ptr<char, decltype(&free)> readers(nullptr, free);
  std::unique_ptr<char, decltype(&free)> ATR(nullptr, free);
  bool panMismatch = false;
  try {
    DWORD len = 0;
    ByteDynArray CertCIE;
    ByteDynArray SOD;

    SCARDCONTEXT hSC;

#if defined(__ANDROID__)
    auto transport = std::make_shared<AndroidNFCTransport>();
#else
    auto transport = std::make_shared<PCSCTransport>();
#endif
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

    readers.reset(static_cast<char*>(malloc(len)));

    if (transport->ListReaders(hSC, readers.get(), &len) != SCARD_S_SUCCESS) {
      return CKR_TOKEN_NOT_PRESENT;
    }

    char* curreader = readers.get();
    bool foundCIE = false;

    progressCallBack(25, "Looking for CIE...");

    for (; curreader[0] != 0; curreader += strnlen(curreader, len) + 1) {
      safeConnection conn(*transport, hSC, curreader, SCARD_SHARE_SHARED);
      if (!conn.hCard) continue;

      DWORD atrLen = 40;
      if (transport->GetAttrib(conn.hCard, SCARD_ATTR_ATR_STRING,
                               reinterpret_cast<uint8_t*>(ATR.get()),
                               &atrLen) != SCARD_S_SUCCESS) {
        return CKR_DEVICE_ERROR;
      }

      ATR.reset(static_cast<char*>(malloc(atrLen)));

      if (transport->GetAttrib(conn.hCard, SCARD_ATTR_ATR_STRING,
                               reinterpret_cast<uint8_t*>(ATR.get()),
                               &atrLen) != SCARD_S_SUCCESS) {
        return CKR_DEVICE_ERROR;
      }

      ByteArray atrBa(reinterpret_cast<BYTE*>(ATR.get()), atrLen);

      auto ias = std::make_unique<IAS>(TokenTransmitCallback, atrBa);
      ias->SetCardContext(&conn);

      ias->token.Reset();
      // Continue looking for a CIE if the token is unrecognised
      try {
        ias->SelectAID_IAS();
      } catch (logged_error& err) {
        ATR.reset();
        continue;
      }
      ias->ReadPAN();

      foundCIE = true;
      ByteDynArray IntAuth;
      ias->SelectAID_CIE();
      ias->ReadDappPubKey(IntAuth);
      ias->SelectAID_CIE();
      ias->InitEncKey();

      ByteDynArray IdServizi;
      ias->ReadIdServizi(IdServizi);
      ByteArray baPan =
          ByteArray(reinterpret_cast<const uint8_t*>(pan), strlen(pan));

      if (baPan.size() > 0 &&
          memcmp(baPan.data(), IdServizi.data(), IdServizi.size()) != 0) {
        panMismatch = true;
        ATR.reset();
        continue;
      }

      progressCallBack(50, "Getting certificate from CIE...");

      ByteDynArray FullPIN;
      ByteArray LastPIN =
          ByteArray(reinterpret_cast<const uint8_t*>(pin), strlen(pin));
      ias->GetFirstPIN(FullPIN);
      FullPIN.append(LastPIN);
      ias->token.Reset();

      progressCallBack(75, "Starting signature...");

      char fullPinCStr[9];
      memcpy(fullPinCStr, FullPIN.data(), 8);
      fullPinCStr[8] = 0;

      auto cieSign = std::make_unique<CIESign>(ias.get());

      uint16_t ret = cieSign->sign(inFilePath, type, fullPinCStr, page, x, y, w,
                                   h, imageData, imageDataLen, outFilePath);
      OPENSSL_cleanse(fullPinCStr, sizeof(fullPinCStr));
      OPENSSL_cleanse(FullPIN.data(), FullPIN.size());
      if ((ret & (0x63C0)) == 0x63C0) {
        return CKR_PIN_INCORRECT;
      } else if (ret == 0x6983) {
        return CKR_PIN_LOCKED;
      }

      progressCallBack(100, "OK!");

      LOG_INFO("cie_sign - completed, res: %d", ret);

      // At this point if there has been a pan mismatch doesn't matter
      panMismatch = false;

      completedCallBack(ret);

      // A this point a CIE has been found, stop looking for it
      break;
    }

    if (!foundCIE) {
      return CKR_TOKEN_NOT_RECOGNIZED;
    }
  } catch (std::exception& ex) {
    LOG_ERROR(ex.what());
    LOG_ERROR("cie_sign - Exception: %s", ex.what());
    LOG_ERROR("cie_sign - General error\n");
    return CKR_GENERAL_ERROR;
  }

  if (panMismatch) return CARD_PAN_MISMATCH;

  return SCARD_S_SUCCESS;
}
