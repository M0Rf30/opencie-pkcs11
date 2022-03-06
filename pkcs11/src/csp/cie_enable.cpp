// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

#include "csp/cie_enable.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <process.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include <cryptopp/asn.h>
#include <cryptopp/config_int.h>
#include <cryptopp/cryptlib.h>
#include <cstring>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <functional>
#include <string>
#include <vector>

#include "csp/ias.h"
#include "crypto/aes.h"
#include "crypto/asn_parser.h"
#include "crypto/crypto_util.h"
#include "crypto/sha256.h"
#include "crypto/sha512.h"
#include "logger/logger.h"
#include "pkcs11/pkcs11_functions.h"
#include "pkcs11/slot.h"
#include "sign/cie_sign.h"
#include "sign/cie_verify.h"
#include "Util/definitions.h"
#include "Util/cryptopp_utils.h"
#include "Util/module_info.h"
#if defined(__ANDROID__)
#include "pcsc/AndroidNFCTransport.h"
#else
#include "pcsc/pcsc_transport.h"
#endif

using namespace CieIDLogger;
using namespace CryptoPP;

#define ROLE_USER 1
#define ROLE_ADMIN 2
#define CARD_ALREADY_ENABLED 0x000000F0;

OID OID_SURNAME = ((OID(2) += 5) += 4) += 4;

OID OID_GIVENNAME = ((OID(2) += 5) += 4) += 42;

extern CModuleInfo moduleInfo;

void GetCertInfo(CryptoPP::BufferedTransformation& certin, std::string& serial,
                 CryptoPP::BufferedTransformation& issuer,
                 CryptoPP::BufferedTransformation& subject,
                 std::string& notBefore, std::string& notAfter,
                 CryptoPP::Integer& mod, CryptoPP::Integer& pubExp);

std::vector<word32> fromObjectIdentifier(std::string sObjId);

DWORD CardAuthenticateEx(IAS* ias, DWORD PinId, DWORD dwFlags, BYTE* pbPinData,
                         DWORD cbPinData, BYTE** ppbSessionPin,
                         DWORD* pcbSessionPin,
                         PROGRESS_CALLBACK progressCallBack,
                         int* pcAttemptsRemaining);

extern "C" {
CK_RV CK_ENTRY cie_enable(const char* szPAN, const char* szPIN, int* attempts,
                          PROGRESS_CALLBACK progressCallBack,
                          COMPLETED_CALLBACK completedCallBack);
CK_RV CK_ENTRY cie_is_enabled(const char* szPAN);
CK_RV CK_ENTRY cie_disable(const char* szPAN);
}

CK_RV CK_ENTRY cie_is_enabled(const char* szPAN) {
  if (IAS::IsEnrolled(szPAN))
    return 1;
  else
    return 0;
}

CK_RV CK_ENTRY cie_disable(const char* szPAN) {
  if (IAS::IsEnrolled(szPAN)) {
    IAS::Unenroll(szPAN);
    LOG_INFO("cie_disable - CIE number %s removed", szPAN);
    return CKR_OK;
  } else {
    LOG_ERROR(
        "cie_disable - Unable to remove CIE number %s, CIE is not enrolled",
        szPAN);
    return CKR_FUNCTION_FAILED;
  }

  return CKR_FUNCTION_FAILED;
}

CK_RV CK_ENTRY cie_enable(const char* szPAN, const char* szPIN, int* attempts,
                          PROGRESS_CALLBACK progressCallBack,
                          COMPLETED_CALLBACK completedCallBack) {
  char* readers = nullptr;
  char* ATR = nullptr;

  LOG_INFO("***** Starting cie_enable *****");
  LOG_DEBUG("szPAN:%s, pin len : %d", szPAN, strlen(szPIN));

  // verifica bontà PIN
  if (szPIN == nullptr || strnlen(szPIN, 9) != 8) {
    return CKR_PIN_LEN_RANGE;
  }

  size_t i = 0;
  while (i < 8 && (szPIN[i] >= '0' && szPIN[i] <= '9')) i++;

  if (i != 8) return CKR_PIN_INVALID;

  try {
    std::map<uint8_t, ByteDynArray> hashSet;

    DWORD len = 0;
    ByteDynArray CertCIE;
    ByteDynArray SOD;
    ByteDynArray IdServizi;

    SCARDCONTEXT hSC;

    LOG_INFO("cie_enable - Connecting to CIE...");
    progressCallBack(1, "Connessione alla CIE");

    #if defined(__ANDROID__)
    auto transport = std::make_shared<AndroidNFCTransport>();
#else
    auto transport = std::make_shared<PCSCTransport>();
#endif
    long nRet = transport->EstablishContext(SCARD_SCOPE_USER, &hSC);
    if (nRet != SCARD_S_SUCCESS) {
      LOG_ERROR("cie_enable - SCardEstablishContext error: %d", nRet);
      return CKR_DEVICE_ERROR;
    }

    nRet = transport->ListReaders(hSC, nullptr, &len);
    if (nRet != SCARD_S_SUCCESS) {
      LOG_ERROR("cie_enable - SCardListReaders error: %d. Len: %d", nRet, len);
      return CKR_TOKEN_NOT_PRESENT;
    }

    if (len == 1) return CKR_TOKEN_NOT_PRESENT;

    readers = static_cast<char*>(malloc(len));

    nRet = transport->ListReaders(hSC, readers, &len);
    if (nRet != SCARD_S_SUCCESS) {
      LOG_ERROR("cie_enable - SCardListReaders error: %d", nRet);
      free(readers);
      return CKR_TOKEN_NOT_PRESENT;
    }

    progressCallBack(5, "CIE Connessa");
    LOG_INFO("cie_enable - CIE Connected");

    char* curreader = readers;
    bool foundCIE = false;
    for (; curreader[0] != 0; curreader += strnlen(curreader, len) + 1) {
      safeConnection conn(*transport, hSC, curreader, SCARD_SHARE_SHARED);
      if (!conn.hCard) continue;

      DWORD atrLen = 40;
      nRet = transport->GetAttrib(conn.hCard, SCARD_ATTR_ATR_STRING, reinterpret_cast<uint8_t*>(ATR),
                            &atrLen);
      if (nRet != SCARD_S_SUCCESS) {
        LOG_ERROR("cie_enable - SCardGetAttrib error, %d\n", nRet);
        free(readers);
        return CKR_DEVICE_ERROR;
      }

      ATR = static_cast<char*>(malloc(atrLen));

      nRet = transport->GetAttrib(conn.hCard, SCARD_ATTR_ATR_STRING, reinterpret_cast<uint8_t*>(ATR),
                            &atrLen);
      if (nRet != SCARD_S_SUCCESS) {
        LOG_ERROR("cie_enable - SCardGetAttrib error, %d\n", nRet);
        free(readers);
        free(ATR);
        return CKR_DEVICE_ERROR;
      }

      ByteArray atrBa(reinterpret_cast<BYTE*>(ATR), atrLen);

      progressCallBack(10, "Verifica carta esistente");

      LOG_DEBUG("cie_enable - Checking if card has been activated yet...");
      IAS ias(TokenTransmitCallback, atrBa);
      ias.SetCardContext(&conn);

      foundCIE = false;

      ias.token.Reset();
      ias.SelectAID_IAS();
      ias.ReadPAN();

      ByteDynArray IntAuth;
      ias.SelectAID_CIE();
      ias.ReadDappPubKey(IntAuth);
      ias.InitEncKey();

      ByteDynArray IdServizi;
      ias.ReadIdServizi(IdServizi);

      if (ias.IsEnrolled()) {
        LOG_ERROR("cie_enable - CIE already enabled. Serial number: %s\n",
                  IdServizi.data());
        return CARD_ALREADY_ENABLED;
      }

      progressCallBack(15, "Lettura dati dalla CIE");
      LOG_INFO("cie_enable - Reading data from CIE...");

      ByteArray serviziData(IdServizi.left(12));

      ByteDynArray SOD;
      ias.ReadSOD(SOD);
      uint8_t digest = ias.GetSODDigestAlg(SOD);

      ByteArray intAuthData(IntAuth.left(GetASN1DataLenght(IntAuth)));

      ByteDynArray IntAuthServizi;
      ias.ReadServiziPubKey(IntAuthServizi);
      ByteArray intAuthServiziData(
          IntAuthServizi.left(GetASN1DataLenght(IntAuthServizi)));

      ias.SelectAID_IAS();
      ByteDynArray DH;
      ias.ReadDH(DH);
      ByteArray dhData(DH.left(GetASN1DataLenght(DH)));

      foundCIE = true;

      progressCallBack(20, "Autenticazione...");

      free(readers);
      readers = nullptr;
      free(ATR);
      ATR = nullptr;

      LONG rs = CardAuthenticateEx(&ias, ROLE_USER, FULL_PIN, reinterpret_cast<BYTE*>(const_cast<char*>(szPIN)),
                                    static_cast<DWORD>(strnlen(szPIN, sizeof(szPIN))),
                                    nullptr, 0, progressCallBack, attempts);
      if (rs == SCARD_W_WRONG_CHV) {
        LOG_ERROR("cie_enable - CardAuthenticateEx Wrong Pin");
        free(ATR);
        free(readers);
        return CKR_PIN_INCORRECT;
      } else if (rs == SCARD_W_CHV_BLOCKED) {
        LOG_ERROR("cie_enable - CardAuthenticateEx Pin locked");
        free(ATR);
        free(readers);
        return CKR_PIN_LOCKED;
      } else if (rs != SCARD_S_SUCCESS) {
        LOG_ERROR("cie_enable - CardAuthenticateEx Generic error, res:%d", rs);
        free(ATR);
        free(readers);
        return CKR_GENERAL_ERROR;
      }

      progressCallBack(45, "Lettura seriale");

      ByteDynArray Serial;
      ias.ReadSerialeCIE(Serial);
      ByteArray serialData = Serial.left(9);
      std::string st_serial(reinterpret_cast<char*>(serialData.data()), serialData.size());

      progressCallBack(55, "Lettura certificato");
      LOG_INFO("cie_enable - Reading certificate...");

      ByteDynArray CertCIE;
      ias.ReadCertCIE(CertCIE);
      ByteArray certCIEData = CertCIE.left(GetASN1DataLenght(CertCIE));

      LOG_INFO("cie_enable - Verifying SOD, digest algorithm: %s",
               (digest == 1) ? "RSA/SHA256" : "RSA-PSS/SHA512");
      if (digest == 1) {
        CSHA256 sha256;
        hashSet[0xa1] = sha256.Digest(serviziData);
        hashSet[0xa4] = sha256.Digest(intAuthData);
        hashSet[0xa5] = sha256.Digest(intAuthServiziData);
        hashSet[0x1b] = sha256.Digest(dhData);
        hashSet[0xa2] = sha256.Digest(serialData);
        hashSet[0xa3] = sha256.Digest(certCIEData);
        ias.VerificaSOD(SOD, hashSet);

      } else {
        CSHA512 sha512;
        hashSet[0xa1] = sha512.Digest(serviziData);
        hashSet[0xa4] = sha512.Digest(intAuthData);
        hashSet[0xa5] = sha512.Digest(intAuthServiziData);
        hashSet[0x1b] = sha512.Digest(dhData);
        hashSet[0xa2] = sha512.Digest(serialData);
        hashSet[0xa3] = sha512.Digest(certCIEData);
        ias.VerificaSODPSS(SOD, hashSet);
      }

      ByteArray pinBa(reinterpret_cast<const uint8_t*>(szPIN), 4);

      progressCallBack(85, "Memorizzazione in cache");
      LOG_INFO("cie_enable - Saving certificate in cache...");

      std::string sidServizi(reinterpret_cast<char*>(IdServizi.data()), IdServizi.size());

      ias.SetCache(const_cast<char*>(sidServizi.c_str()), CertCIE, pinBa);

      std::string span(const_cast<char*>(sidServizi.c_str()));
      std::string name;
      std::string surname;

      CryptoPP::ByteQueue certin;
      certin.Put(CertCIE.data(), CertCIE.size());

      std::string serial;
      CryptoPP::ByteQueue issuer;
      CryptoPP::ByteQueue subject;
      std::string notBefore;
      std::string notAfter;
      CryptoPP::Integer mod;
      CryptoPP::Integer pubExp;

      GetCertInfo(certin, serial, issuer, subject, notBefore, notAfter, mod,
                  pubExp);

      CryptoPP::BERSequenceDecoder subjectEncoder(subject);
      {
        while (!subjectEncoder.EndReached()) {
          CryptoPP::BERSetDecoder item(subjectEncoder);
          CryptoPP::BERSequenceDecoder attributes(item);
          {
            OID oid(attributes);
            if (oid == OID_GIVENNAME) {
              CryptoPP::byte tag = 0;
              attributes.Peek(tag);

              CryptoPP::BERDecodeTextString(attributes, name, tag);
            } else if (oid == OID_SURNAME) {
              CryptoPP::byte tag = 0;
              attributes.Peek(tag);

              CryptoPP::BERDecodeTextString(attributes, surname, tag);
            }

            item.SkipAll();
          }
        }
      }

      subjectEncoder.SkipAll();

      std::string fullname = name + " " + surname;
      completedCallBack(span.c_str(), fullname.c_str(), st_serial.c_str());
    }

    if (!foundCIE) {
      LOG_ERROR("cie_enable - No CIE available");
      free(ATR);
      free(readers);
      return CKR_TOKEN_NOT_RECOGNIZED;
    }

  } catch (std::exception& ex) {
    LOG_ERROR("cie_enable - Exception %s ", ex.what());
    if (ATR) free(ATR);

    if (readers) free(readers);
    return CKR_GENERAL_ERROR;
  }

  if (ATR) free(ATR);
  if (readers) free(readers);

  LOG_INFO("cie_enable - CIE paired successfully");
  progressCallBack(100, "OK!");
  LOG_INFO("***** cie_enable Ended *****");

  return SCARD_S_SUCCESS;
}

DWORD CardAuthenticateEx(IAS* ias, DWORD PinId, DWORD dwFlags, BYTE* pbPinData,
                         DWORD cbPinData, BYTE** /*ppbSessionPin*/,
                         DWORD* pcbSessionPin,
                         PROGRESS_CALLBACK progressCallBack,
                         int* pcAttemptsRemaining) {
  LOG_INFO("***** Starting CardAuthenticateEx *****");
  LOG_DEBUG(
      "Pin id: %d, dwFlags: %d, cbPinData: %d, pbSessionPin: %s, "
      "pcAttemptsRemaining: %d",
      PinId, dwFlags, cbPinData, pcbSessionPin, *pcAttemptsRemaining);

  LOG_INFO("CardAuthenticateEx - Selecting IAS and CIE AID");

  progressCallBack(21, "selected CIE applet");
  ias->SelectAID_IAS();
  ias->SelectAID_CIE();

  progressCallBack(22, "init DH Param");
  // leggo i parametri di dominio DH e della chiave di extauth
  LOG_INFO("CardAuthenticateEx - Reading DH parameters");

  ias->InitDHParam();

  progressCallBack(24, "read DappPubKey");

  ByteDynArray dappData;
  ias->ReadDappPubKey(dappData);

  LOG_INFO("CardAuthenticateEx - Performing DH Exchange");

  progressCallBack(26, "InitExtAuthKeyParam");
  ias->InitExtAuthKeyParam();

  progressCallBack(28, "DHKeyExchange");
  ias->DHKeyExchange();

  progressCallBack(30, "DAPP");

  // DAPP
  ias->DAPP();

  progressCallBack(32, "VerifyPIN");

  // verifica PIN
  StatusWord sw;
  if (PinId == ROLE_USER) {
    LOG_INFO("CardAuthenticateEx - Verifying PIN");
    ByteDynArray PIN;
    if ((dwFlags & FULL_PIN) != FULL_PIN) ias->GetFirstPIN(PIN);
    PIN.append(ByteArray(pbPinData, cbPinData));
    sw = ias->VerifyPIN(PIN);
  } else if (PinId == ROLE_ADMIN) {
    LOG_INFO("CardAuthenticateEx - Verifying PUK");
    ByteArray pinBa(pbPinData, cbPinData);
    sw = ias->VerifyPUK(pinBa);
  } else {
    LOG_ERROR("CardAuthenticateEx - Invalid parameter: wrong PinId value");
    return SCARD_E_INVALID_PARAMETER;
  }

  progressCallBack(34, "verifyPIN ok");

  if (sw == 0x6983) {
    LOG_ERROR("CardAuthenticateEx - Pin locked");
    return SCARD_W_CHV_BLOCKED;
  }
  if (sw >= 0x63C0 && sw <= 0x63CF) {
    if (pcAttemptsRemaining != nullptr) *pcAttemptsRemaining = sw - 0x63C0;
    LOG_ERROR("CardAuthenticateEx - Wrong Pin");
    return SCARD_W_WRONG_CHV;
  }
  if (sw == 0x6700) {
    LOG_ERROR("CardAuthenticateEx - Wrong Pin");
    return SCARD_W_WRONG_CHV;
  }
  if (sw == 0x6300) {
    LOG_ERROR("CardAuthenticateEx - Wrong Pin");
    return SCARD_W_WRONG_CHV;
  }
  if (sw != 0x9000) {
    LOG_ERROR("CarduAuthenticateEx - Smart Card error: 0x%04X", sw);
  }

  LOG_INFO("***** CardAuthenticateEx Ended *****");
  return SCARD_S_SUCCESS;
}

HRESULT TokenTransmitCallback(void* data, BYTE* apdu, DWORD apduSize,
                          BYTE* resp, DWORD* respSize) {
  auto* conn = static_cast<safeConnection*>(data);
  LOG_DEBUG("TokenTransmitCallback - Apdu:");
  LOG_BUFFER(apdu, apduSize);

  if (apduSize == 2) {
    WORD code = *reinterpret_cast<WORD*>(apdu);
    if (code == 0xfffd) {
      *respSize = sizeof(conn->hCard) + 2;
      std::memcpy(resp, &conn->hCard, sizeof(conn->hCard));
      resp[sizeof(&conn->hCard)] = 0;
      resp[sizeof(&conn->hCard) + 1] = 0;

      return SCARD_S_SUCCESS;
    } else if (code == 0xfffe) {
      DWORD protocol = 0;
      LOG_INFO("TokenTransmitCallback - Unpowering Card");
      auto ris =
          conn->transport.Reconnect(conn->hCard, SCARD_SHARE_SHARED, SCARD_PROTOCOL_Tx,
                         SCARD_UNPOWER_CARD, &protocol);

      if (ris == SCARD_S_SUCCESS) {
        conn->transport.BeginTransaction(conn->hCard);
        *respSize = 2;
        resp[0] = 0x90;
        resp[1] = 0x00;
      }
      return ris;
    } else if (code == 0xffff) {
      DWORD protocol = 0;
      auto ris = conn->transport.Reconnect(conn->hCard, SCARD_SHARE_SHARED,
                                SCARD_PROTOCOL_Tx, SCARD_RESET_CARD, &protocol);
      if (ris == SCARD_S_SUCCESS) {
        conn->transport.BeginTransaction(conn->hCard);
        *respSize = 2;
        resp[0] = 0x90;
        resp[1] = 0x00;
      }
      LOG_INFO("TokenTransmitCallback - Resetting Card");

      return ris;
    }
  }
  auto ris = conn->transport.Transmit(conn->hCard, SCARD_PCI_T1, apdu, apduSize,
                           resp, respSize);

  LOG_DEBUG("TokenTransmitCallback - Smart card response:");
  LOG_BUFFER(resp, *respSize);

  if (ris == SCARD_W_RESET_CARD || ris == SCARD_W_UNPOWERED_CARD) {
    LOG_INFO("TokenTransmitCallback - Card Reset done");

    DWORD protocol = 0;
    ris = conn->transport.Reconnect(conn->hCard, SCARD_SHARE_SHARED, SCARD_PROTOCOL_Tx,
                         SCARD_LEAVE_CARD, &protocol);
    if (ris != SCARD_S_SUCCESS)
      LOG_ERROR("TokenTransmitCallback - ScardReconnect error: %d", ris);
    else {
      ris = conn->transport.Transmit(conn->hCard, SCARD_PCI_T1, apdu, apduSize, resp,
                          respSize);
      LOG_DEBUG("TokenTransmitCallback - Smart card response:");
      LOG_BUFFER(resp, *respSize);
    }
  }

  if (ris != SCARD_S_SUCCESS) {
    LOG_ERROR("TokenTransmitCallback - SCardTransmit error: %d", ris);
  }
  return ris;
}

std::vector<word32> fromObjectIdentifier(std::string sObjId) {
  std::vector<word32> out;

  int nVal;
  int nAux;
  char* szTok;
  std::vector<char> oidBuf(sObjId.size() + 1);
  char* szOID = oidBuf.data();
  memcpy(szOID, sObjId.c_str(), sObjId.size());
  char* next = nullptr;
  szTok = strtok_r(szOID, ".", &next);

  UINT nFirst = 40 * strtol(szTok, nullptr, 10) +
                strtol(strtok_r(nullptr, ".", &next), nullptr, 10);
  if (nFirst > 0xff) {
    throw -1;
  }

  out.push_back(nFirst);

  int i = 0;

  while ((szTok = strtok_r(nullptr, ".", &next)) != nullptr) {
    nVal = strtol(szTok, nullptr, 10);
    if (nVal == 0) {
      out.push_back(0x00);
    } else if (nVal == 1) {
      out.push_back(0x01);
    } else {
      i = static_cast<int>(ceil((log(static_cast<double>(abs(nVal))) / log(static_cast<double>(2))) / 7));  // base 128
      while (nVal != 0) {
        nAux = static_cast<int>(floor(nVal / pow(128, i - 1)));
        nVal = nVal - static_cast<int>(pow(128, i - 1) * nAux);

        // next value (or with 0x80)
        if (nVal != 0) nAux |= 0x80;

        out.push_back(nAux);

        i--;
      }
    }
  }

  return out;
}
bool file_exists(const char* name);

char command[1000];

#ifdef _WIN32
DWORD WINAPI mythread(LPVOID thr_data) {
  char* command = static_cast<char*>(thr_data);
  system(command);
  return 0;
}
#else
void* mythread(void* thr_data) {
  char* command = static_cast<char*>(thr_data);
  system(command);

  return nullptr;
}
#endif

int sendMessage(const char* szCommand, const char* /*szParam*/) {
  const char* file = "cieid";

  snprintf(command, 1000, "%s %s", file, szCommand);

#ifdef _WIN32
  HANDLE hThread = CreateThread(nullptr, 0, mythread, static_cast<void*>(command), 0, nullptr);
  if (hThread) CloseHandle(hThread);
#else
  pthread_t thr;
  pthread_create(&thr, nullptr, mythread, static_cast<void*>(command));
#endif

  return 0;
}

void notifyPINLocked() { sendMessage("pinlocked", nullptr); }

void notifyPINWrong(int trials) {
  char szParam[3];
  snprintf(szParam, 3, "%d", trials);

  sendMessage("pinwrong", szParam);
}

void notifyCardNotRegistered(const char* szPAN) {
  sendMessage("cardnotregistered", szPAN);
}
