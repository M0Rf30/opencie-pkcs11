// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

#include "csp/pin_manager.h"

#include <cryptopp/misc.h>

#include <string>

#include "csp/cie_enable.h"
#include "csp/ias.h"
#include "logger/logger.h"
#include "pcsc/pcsc.h"
#include "pkcs11/pkcs11_functions.h"
#include "util/module_info.h"
#if defined(__ANDROID__)
#include "pcsc/android_nfc_transport.h"
#else
#include "pcsc/pcsc_transport.h"
#endif

using namespace CieIDLogger;

extern "C" {
CK_RV CK_ENTRY cie_change_pin(const char* szCurrentPIN, const char* szNewPIN,
                              int* pAttempts,
                              PROGRESS_CALLBACK progressCallBack);
CK_RV CK_ENTRY cie_unblock_pin(const char* szPUK, const char* szNewPIN,
                               int* pAttempts,
                               PROGRESS_CALLBACK progressCallBack);
}

HRESULT TokenTransmitCallback(void* data, uint8_t* apdu, DWORD apduSize,
                              uint8_t* resp, DWORD* respSize);

CK_RV CK_ENTRY cie_change_pin(const char* szCurrentPIN, const char* szNewPIN,
                              int* pAttempts,
                              PROGRESS_CALLBACK progressCallBack) {
  char* readers = nullptr;
  char* ATR = nullptr;

  LOG_INFO("******** Starting PINManager::ChangePIN ********");
  // verifica bontà PIN
  if (szCurrentPIN == nullptr || strnlen(szCurrentPIN, 9) != 8)
    return CKR_PIN_LEN_RANGE;

  if (szNewPIN == nullptr || strnlen(szNewPIN, 9) != 8)
    return CKR_PIN_LEN_RANGE;
  try {
    DWORD len = 0;

    SCARDCONTEXT hSC;

    progressCallBack(10, "Connessione alla CIE");

    LOG_DEBUG("PINManager::ChangePIN - SCardEstablishContext");
#if defined(__ANDROID__)
    auto transport = std::make_shared<AndroidNFCTransport>();
#else
    auto transport = std::make_shared<PCSCTransport>();
#endif
    long nRet = transport->EstablishContext(SCARD_SCOPE_USER, &hSC);
    if (nRet != SCARD_S_SUCCESS) {
      LOG_ERROR("PINManager::ChangePIN - res: %d", nRet);
      return CKR_DEVICE_ERROR;
    }

    LOG_DEBUG("PINManager::ChangePIN - SCardListReaders");

    nRet = transport->ListReaders(hSC, nullptr, &len);
    if (nRet != SCARD_S_SUCCESS) {
      LOG_ERROR("PINManager::ChangePIN - res: %d", nRet);
      return CKR_TOKEN_NOT_PRESENT;
    }

    if (len == 1) {
      LOG_ERROR("PINManager::ChangePIN - No readers");
      return CKR_TOKEN_NOT_PRESENT;
    }

    readers = static_cast<char*>(malloc(len));

    nRet = transport->ListReaders(hSC, readers, &len);
    if (nRet != SCARD_S_SUCCESS) {
      free(readers);
      return CKR_TOKEN_NOT_PRESENT;
    }

    LOG_INFO("PINManager::ChangePIN - CIE connected");
    progressCallBack(10, "CIE Connessa");

    char* curreader = readers;
    bool foundCIE = false;

    for (; curreader[0] != 0; curreader += strnlen(curreader, len) + 1) {
      safeConnection conn(*transport, hSC, curreader, SCARD_SHARE_SHARED);
      if (!conn.hCard) continue;

      DWORD atrLen = 40;
      nRet = transport->GetAttrib(conn.hCard, SCARD_ATTR_ATR_STRING,
                                  reinterpret_cast<uint8_t*>(ATR), &atrLen);
      if (nRet != SCARD_S_SUCCESS) {
        LOG_ERROR("PINManager::ChangePIN - SCardGetAttrib err: %d", nRet);
        free(readers);
        return CKR_DEVICE_ERROR;
      }

      ATR = static_cast<char*>(malloc(atrLen));

      nRet = transport->GetAttrib(conn.hCard, SCARD_ATTR_ATR_STRING,
                                  reinterpret_cast<uint8_t*>(ATR), &atrLen);
      if (nRet != SCARD_S_SUCCESS) {
        LOG_ERROR("PINManager::ChangePIN - SCardGetAttrib err: %d", nRet);
        free(readers);
        free(ATR);
        return CKR_DEVICE_ERROR;
      }

      ByteArray atrBa(reinterpret_cast<BYTE*>(ATR), atrLen);

      IAS ias(TokenTransmitCallback, atrBa);
      ias.SetCardContext(&conn);
      ias.attemptsRemaining = -1;

      ias.token.Reset();
      // Continue looking for CIE if the token is unrecognised
      try {
        ias.SelectAID_IAS();
      } catch (logged_error& err) {
        free(ATR);
        ATR = nullptr;
        continue;
      }
      ias.ReadPAN();

      progressCallBack(20, "Lettura dati dalla CIE");

      ByteDynArray resp;
      ias.SelectAID_CIE();

      ias.InitEncKey();
      ias.ReadDappPubKey(resp);

      foundCIE = true;

      // leggo i parametri di dominio DH e della chiave di extauth
      ias.InitDHParam();

      ias.InitExtAuthKeyParam();

      progressCallBack(40, "Autenticazione...");

      ias.DHKeyExchange();

      // DAPP
      ias.DAPP();

      progressCallBack(80, "Cambio PIN...");

      ByteArray oldPINBa(reinterpret_cast<const uint8_t*>(szCurrentPIN),
                         strlen(szCurrentPIN));

      StatusWord sw = ias.VerifyPIN(oldPINBa);
      LOG_INFO("PINManager::VerifyPIN verify PIN status: %02X", sw);

      if (sw == 0x6983) {
        free(readers);
        free(ATR);
        return CKR_PIN_LOCKED;
      }
      if (sw >= 0x63C0 && sw <= 0x63CF) {
        if (pAttempts != nullptr) *pAttempts = sw - 0x63C0;

        free(readers);
        free(ATR);
        return CKR_PIN_INCORRECT;
      }

      if (sw == 0x6700) {
        free(readers);
        free(ATR);
        return CKR_PIN_INCORRECT;
      }
      if (sw == 0x6300) {
        free(readers);
        free(ATR);
        return CKR_PIN_INCORRECT;
      }
      if (sw != 0x9000) {
        throw scard_error(sw);
      }

      ByteDynArray cert;
      bool isEnrolled = ias.IsEnrolled();

      if (isEnrolled) ias.GetCertificate(cert);

      ByteArray newPINBa(reinterpret_cast<const uint8_t*>(szNewPIN),
                         strlen(szNewPIN));

      sw = ias.ChangePIN(oldPINBa, newPINBa);
      LOG_INFO("PINManager::ChangePIN change PIN status: %02X", sw);
      if (sw != 0x9000) {
        throw scard_error(sw);
      }

      if (isEnrolled) {
        std::string strPAN;
        dumpHexData(ias.PAN.mid(5, 6), strPAN, false);
        ByteArray leftPINBa = newPINBa.left(4);
        ias.SetCache(strPAN.c_str(), cert, leftPINBa);
      }

      progressCallBack(100, "Cambio PIN eseguito");
      LOG_INFO("******** PINManager::ChangePIN Completed ********");

      // A this point a CIE has been found, stop looking for it
      break;
    }

    if (!foundCIE) {
      free(readers);
      free(ATR);
      return CKR_TOKEN_NOT_RECOGNIZED;
    }
  } catch (...) {
    if (readers) free(readers);
    if (ATR) free(ATR);
    return CKR_GENERAL_ERROR;
  }

  if (readers) free(readers);
  if (ATR) free(ATR);

  return CKR_OK;
}

CK_RV CK_ENTRY cie_unblock_pin(const char* szPUK, const char* szNewPIN,
                               int* pAttempts,
                               PROGRESS_CALLBACK progressCallBack) {
  char* readers = nullptr;
  char* ATR = nullptr;
  LOG_INFO("******** Starting PINManager::cie_unblock_pin ********");
  // verifica bontà PIN
  if (szPUK == nullptr || strnlen(szPUK, 9) != 8) return CKR_PIN_LEN_RANGE;

  if (szNewPIN == nullptr || strnlen(szNewPIN, 9) != 8)
    return CKR_PIN_LEN_RANGE;
  try {
    DWORD len = 0;

    SCARDCONTEXT hSC;

    progressCallBack(10, "Connessione alla CIE");

    LOG_DEBUG("PINManager::UnlockPIN - SCardEstablishContext");
#if defined(__ANDROID__)
    auto transport = std::make_shared<AndroidNFCTransport>();
#else
    auto transport = std::make_shared<PCSCTransport>();
#endif
    long nRet = transport->EstablishContext(SCARD_SCOPE_USER, &hSC);
    if (nRet != SCARD_S_SUCCESS) {
      LOG_ERROR("PINManager::UnlockPIN - SCardEstablishContext err: %d", nRet);
      return CKR_DEVICE_ERROR;
    }

    if (transport->ListReaders(hSC, nullptr, &len) != SCARD_S_SUCCESS) {
      LOG_ERROR("PINManager::UnlockPIN - SCardEstablishContext err: %d", nRet);
      return CKR_TOKEN_NOT_PRESENT;
    }

    if (len == 1) {
      LOG_ERROR("PINManager::UnlockPIN - No readers");
      return CKR_TOKEN_NOT_PRESENT;
    }

    readers = static_cast<char*>(malloc(len));

    if (transport->ListReaders(hSC, readers, &len) != SCARD_S_SUCCESS) {
      free(readers);
      return CKR_TOKEN_NOT_PRESENT;
    }

    LOG_INFO("PINManager::UnlockPIN - CIE connected");
    progressCallBack(20, "CIE Connessa");

    char* curreader = readers;
    bool foundCIE = false;

    for (; curreader[0] != 0; curreader += strnlen(curreader, len) + 1) {
      safeConnection conn(*transport, hSC, curreader, SCARD_SHARE_SHARED);
      if (!conn.hCard) continue;

      DWORD atrLen = 40;
      if (transport->GetAttrib(conn.hCard, SCARD_ATTR_ATR_STRING,
                               reinterpret_cast<uint8_t*>(ATR),
                               &atrLen) != SCARD_S_SUCCESS) {
        LOG_ERROR("PINManager::UnlockPIN - SCardGetAttrib err: %d", nRet);
        free(readers);
        return CKR_DEVICE_ERROR;
      }

      ATR = static_cast<char*>(malloc(atrLen));

      if (transport->GetAttrib(conn.hCard, SCARD_ATTR_ATR_STRING,
                               reinterpret_cast<uint8_t*>(ATR),
                               &atrLen) != SCARD_S_SUCCESS) {
        free(readers);
        free(ATR);
        return CKR_DEVICE_ERROR;
      }

      ByteArray atrBa(reinterpret_cast<BYTE*>(ATR), atrLen);

      IAS ias(TokenTransmitCallback, atrBa);
      ias.SetCardContext(&conn);
      ias.attemptsRemaining = -1;

      ias.token.Reset();
      // Continue looking for CIE if the token is unrecognised
      try {
        ias.SelectAID_IAS();
      } catch (logged_error& err) {
        free(ATR);
        ATR = nullptr;
        continue;
      }
      ias.ReadPAN();

      progressCallBack(30, "Lettura dati dalla CIE");

      ByteDynArray resp;
      ias.SelectAID_CIE();

      ias.InitEncKey();
      ias.ReadDappPubKey(resp);

      foundCIE = true;

      // leggo i parametri di dominio DH e della chiave di extauth
      ias.InitDHParam();

      ias.InitExtAuthKeyParam();

      progressCallBack(50, "Autenticazione...");

      ias.DHKeyExchange();

      // DAPP
      ias.DAPP();

      progressCallBack(80, "Sblocco carta...");

      ByteArray pukBa(reinterpret_cast<const uint8_t*>(szPUK), strlen(szPUK));

      StatusWord sw = ias.VerifyPUK(pukBa);
      LOG_INFO("PINManager::UnlockPIN VerifyPUK status: %02X", sw);

      if (sw == 0x6983) {
        free(ATR);
        free(readers);
        return CKR_PIN_LOCKED;
      }
      if (sw >= 0x63C0 && sw <= 0x63CF) {
        free(ATR);
        free(readers);
        if (pAttempts != nullptr) *pAttempts = sw - 0x63C0;

        return CKR_PIN_INCORRECT;
      }

      if (sw == 0x6700) {
        free(ATR);
        free(readers);
        return CKR_PIN_INCORRECT;
      }
      if (sw == 0x6300) {
        free(ATR);
        free(readers);
        return CKR_PIN_INCORRECT;
      }
      if (sw != 0x9000) {
        throw scard_error(sw);
      }

      ByteDynArray cert;
      bool isEnrolled = ias.IsEnrolled();

      if (isEnrolled) ias.GetCertificate(cert);

      ByteArray newPINBa(reinterpret_cast<const uint8_t*>(szNewPIN),
                         strlen(szNewPIN));

      sw = ias.ChangePIN(newPINBa);
      LOG_INFO("PINManager::UnlockPIN ChangePIN status: %02X", sw);
      if (sw != 0x9000) {
        throw scard_error(sw);
      }

      if (isEnrolled) {
        std::string strPAN;
        dumpHexData(ias.PAN.mid(5, 6), strPAN, false);
        ByteArray leftPINBa = newPINBa.left(4);
        ias.SetCache(strPAN.c_str(), cert, leftPINBa);
      }

      progressCallBack(100, "Sblocco carta eseguito");
      LOG_INFO("******** PINManager::UnlockPIN Completed ********");

      // A this point a CIE has been found, stop looking for it
      break;
    }

    if (!foundCIE) {
      free(ATR);
      free(readers);
      return CKR_TOKEN_NOT_RECOGNIZED;
    }

    LOG_INFO("******** PINManager::cie_unblock_pin Completed ********");
  } catch (...) {
    if (ATR) free(ATR);

    if (readers) free(readers);

    return CKR_GENERAL_ERROR;
  }

  if (ATR) free(ATR);

  if (readers) free(readers);

  return CKR_OK;
}
