// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "csp/cie_enable.h"

#ifdef _WIN32
#include <process.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <thread>
#endif

#ifndef _WIN32
// posix_spawn() needs the process environment; not every libc declares
// this in <unistd.h> without _GNU_SOURCE, so declare it explicitly.
extern char** environ;
#endif

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <time.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <stdexcept>
#include <string>
#include <vector>

#include "crypto/aes.h"
#include "crypto/asn_parser.h"
#include "crypto/crypto_util.h"
#include "crypto/sha256.h"
#include "crypto/sha512.h"
#include "csp/cie_error.h"
#include "csp/ias.h"
#include "logger/logger.h"
#include "pkcs11/pkcs11_functions.h"
#include "pkcs11/slot.h"
#include "sign/cie_sign.h"
#include "sign/cie_verify.h"
#include "util/cache_lib.h"
#include "util/definitions.h"
#include "util/module_info.h"
#if defined(__ANDROID__)
#include "pcsc/android_nfc_transport.h"
#else
#include "pcsc/pcsc_transport.h"
#endif

using namespace CieIDLogger;

#define ROLE_USER 1
#define ROLE_ADMIN 2
#define CARD_ALREADY_ENABLED 0x000000F0;

/// Hex-encode arbitrary bytes so the result is safe as a UTF-8 string and
/// as a filesystem filename.  Used to encode the binary EF.IdServizi PAN
/// before passing it to the COMPLETED_CALLBACK (and ultimately to Dart).
static std::string hexEncode(const uint8_t* data, size_t len) {
  static const char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(len * 2);
  for (size_t i = 0; i < len; ++i) {
    out += kHex[(data[i] >> 4) & 0xF];
    out += kHex[data[i] & 0xF];
  }
  return out;
}

extern CModuleInfo moduleInfo;

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
int CK_ENTRY cie_reader_count(void);
int CK_ENTRY cie_reader_watch(int current_count);
int CK_ENTRY cie_reader_name(char* buf, int buf_len);
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

CK_RV CK_ENTRY cie_enable(const char* /*szPAN*/, const char* szPIN,
                          int* attempts, PROGRESS_CALLBACK progressCallBack,
                          COMPLETED_CALLBACK completedCallBack) {
  char* readers = nullptr;
  char* ATR = nullptr;

  LOG_INFO("***** Starting cie_enable *****");

  // Validate PIN before use
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

    progressCallBack(5, "CIE Connected");
    LOG_INFO("cie_enable - CIE Connected");

    char* curreader = readers;
    bool foundCIE = false;
    for (; curreader[0] != 0; curreader += strnlen(curreader, len) + 1) {
      safeConnection conn(*transport, hSC, curreader, SCARD_SHARE_SHARED);
      if (!conn.hCard) continue;

      DWORD atrLen = 40;
      nRet = transport->GetAttrib(conn.hCard, SCARD_ATTR_ATR_STRING,
                                  reinterpret_cast<uint8_t*>(ATR), &atrLen);
      if (nRet != SCARD_S_SUCCESS) {
        LOG_ERROR("cie_enable - SCardGetAttrib error, %d\n", nRet);
        free(readers);
        return CKR_DEVICE_ERROR;
      }

      ATR = static_cast<char*>(malloc(atrLen));

      nRet = transport->GetAttrib(conn.hCard, SCARD_ATTR_ATR_STRING,
                                  reinterpret_cast<uint8_t*>(ATR), &atrLen);
      if (nRet != SCARD_S_SUCCESS) {
        LOG_ERROR("cie_enable - SCardGetAttrib error, %d\n", nRet);
        free(readers);
        free(ATR);
        return CKR_DEVICE_ERROR;
      }

      ByteArray atrBa(reinterpret_cast<BYTE*>(ATR), atrLen);

      progressCallBack(10, "Verifying existing card");

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

      ByteDynArray IdServizi2;
      ias.ReadIdServizi(IdServizi2);

      if (ias.IsEnrolled()) {
        LOG_INFO("cie_enable - CIE already enabled. Serial number: %s\n",
                 IdServizi2.data());

        // Use PAN.mid(5,6) — same key as IAS::IsEnrolled() / GetCertificate()
        std::string sidServizi_already = hexEncode(ias.PAN.data() + 5, 6);

        completedCallBack(sidServizi_already.c_str(), "", "");

        free(readers);
        readers = nullptr;
        free(ATR);
        ATR = nullptr;

        progressCallBack(100, "OK!");
        cie_clear_error();
        return SCARD_S_SUCCESS;
      }

      progressCallBack(15, "Lettura dati dalla CIE");
      LOG_INFO("cie_enable - Reading data from CIE...");

      ByteArray serviziData(IdServizi2.left(12));

      ByteDynArray SOD2;
      ias.ReadSOD(SOD2);
      uint8_t digest = ias.GetSODDigestAlg(SOD2);

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

      progressCallBack(20, "Authenticating...");

      free(readers);
      readers = nullptr;
      free(ATR);
      ATR = nullptr;

      LONG rs =
          CardAuthenticateEx(&ias, ROLE_USER, FULL_PIN,
                             reinterpret_cast<BYTE*>(const_cast<char*>(szPIN)),
                             static_cast<DWORD>(strnlen(szPIN, 9)), nullptr, 0,
                             progressCallBack, attempts);
      if (rs == static_cast<LONG>(SCARD_W_WRONG_CHV)) {
        LOG_ERROR("cie_enable - CardAuthenticateEx Wrong Pin");
        free(ATR);
        free(readers);
        return CKR_PIN_INCORRECT;
      } else if (rs == static_cast<LONG>(SCARD_W_CHV_BLOCKED)) {
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
      std::string st_serial(reinterpret_cast<char*>(serialData.data()),
                            serialData.size());

      progressCallBack(55, "Lettura certificato");
      LOG_INFO("cie_enable - Reading certificate...");

      ByteDynArray CertCIE2;
      ias.ReadCertCIE(CertCIE2);
      ByteArray certCIEData = CertCIE2.left(GetASN1DataLenght(CertCIE2));

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
        ias.VerificaSOD(SOD2, hashSet);

      } else {
        CSHA512 sha512;
        hashSet[0xa1] = sha512.Digest(serviziData);
        hashSet[0xa4] = sha512.Digest(intAuthData);
        hashSet[0xa5] = sha512.Digest(intAuthServiziData);
        hashSet[0x1b] = sha512.Digest(dhData);
        hashSet[0xa2] = sha512.Digest(serialData);
        hashSet[0xa3] = sha512.Digest(certCIEData);
        ias.VerificaSODPSS(SOD2, hashSet);
      }

      ByteArray pinBa(reinterpret_cast<const uint8_t*>(szPIN), 4);

      progressCallBack(85, "Memorizzazione in cache");
      LOG_INFO("cie_enable - Saving certificate in cache...");

      std::string sidServizi(reinterpret_cast<char*>(IdServizi.data()),
                             IdServizi.size());

      // Use PAN.mid(5,6) as cache key — same as IAS::IsEnrolled() /
      // GetCertificate() so lookups after enrollment succeed.
      std::string span = hexEncode(ias.PAN.data() + 5, 6);

      ias.SetCache(const_cast<char*>(span.c_str()), CertCIE2, pinBa);
      // Also store the raw DER cert so cie_get_certificate() can return it
      // without needing a live PACE session.
      CacheSetDer(span.c_str(), CertCIE2.data(), CertCIE2.size());
      // Zero the PIN buffer as soon as it is no longer needed.
      OPENSSL_cleanse(pinBa.data(), pinBa.size());
      std::string name;
      std::string surname;

      // Parse cert with OpenSSL to extract name/surname
      const unsigned char* p = CertCIE2.data();
      X509* x509 = d2i_X509(nullptr, &p, static_cast<long>(CertCIE2.size()));
      if (!x509) throw logged_error("Failed to parse CIE certificate");

      X509_NAME* subj = X509_get_subject_name(x509);
      int idx = X509_NAME_get_index_by_NID(subj, NID_givenName, -1);
      if (idx >= 0) {
        X509_NAME_ENTRY* entry = X509_NAME_get_entry(subj, idx);
        ASN1_STRING* val = X509_NAME_ENTRY_get_data(entry);
        unsigned char* utf8 = nullptr;
        int nameLen = ASN1_STRING_to_UTF8(&utf8, val);
        if (nameLen > 0) {
          name.assign(reinterpret_cast<char*>(utf8), nameLen);
          OPENSSL_free(utf8);
        }
      }
      idx = X509_NAME_get_index_by_NID(subj, NID_surname, -1);
      if (idx >= 0) {
        X509_NAME_ENTRY* entry = X509_NAME_get_entry(subj, idx);
        ASN1_STRING* val = X509_NAME_ENTRY_get_data(entry);
        unsigned char* utf8 = nullptr;
        int nameLen = ASN1_STRING_to_UTF8(&utf8, val);
        if (nameLen > 0) {
          surname.assign(reinterpret_cast<char*>(utf8), nameLen);
          OPENSSL_free(utf8);
        }
      }
      X509_free(x509);

      std::string fullname = name + " " + surname;
      completedCallBack(span.c_str(), fullname.c_str(), st_serial.c_str());
    }

    if (!foundCIE) {
      LOG_ERROR("cie_enable - No CIE available");
      free(ATR);
      free(readers);
      return CKR_TOKEN_NOT_RECOGNIZED;
    }

  } catch (scard_error& e) {
    LOG_ERROR("cie_enable - Smart card error: 0x%04X", e.sw);
    cie_record_sw_error(e.sw);
    if (ATR) free(ATR);
    if (readers) free(readers);
    cie_error_kind kind = cie_classify_sw(e.sw);
    if (kind == CIE_ERR_PIN_BLOCKED) return CKR_PIN_LOCKED;
    if (kind == CIE_ERR_WRONG_PIN) return CKR_PIN_INCORRECT;
    if (kind == CIE_ERR_CARD_COMMUNICATION) return CKR_DEVICE_ERROR;
    return CKR_GENERAL_ERROR;
  } catch (std::exception& ex) {
    LOG_ERROR("cie_enable - Exception %s ", ex.what());
    cie_record_transport_error();
    if (ATR) free(ATR);
    if (readers) free(readers);
    return CKR_GENERAL_ERROR;
  } catch (...) {
    LOG_ERROR("cie_enable - Unknown exception");
    cie_record_transport_error();
    if (ATR) free(ATR);
    if (readers) free(readers);
    return CKR_GENERAL_ERROR;
  }

  if (ATR) free(ATR);
  if (readers) free(readers);

  LOG_INFO("cie_enable - CIE paired successfully");
  progressCallBack(100, "OK!");
  LOG_INFO("***** cie_enable Ended *****");

  cie_clear_error();
  return SCARD_S_SUCCESS;
}

DWORD CardAuthenticateEx(IAS* ias, DWORD PinId, DWORD dwFlags, BYTE* pbPinData,
                         DWORD cbPinData, BYTE** /*ppbSessionPin*/,
                         DWORD* pcbSessionPin,
                         PROGRESS_CALLBACK progressCallBack,
                         int* pcAttemptsRemaining) {
  LOG_INFO("***** Starting CardAuthenticateEx *****");
  LOG_DEBUG("Pin id: %d, dwFlags: %d, cbPinData: %d, pbSessionPin: %s", PinId,
            dwFlags, cbPinData, pcbSessionPin);

  LOG_INFO("CardAuthenticateEx - Selecting IAS and CIE AID");

  progressCallBack(21, "selected CIE applet");
  ias->SelectAID_IAS();
  ias->SelectAID_CIE();

  progressCallBack(22, "init DH Param");
  LOG_INFO("CardAuthenticateEx - Reading DH parameters");
  ias->InitDHParam();

  progressCallBack(24, "read DappPubKey");

  // Only read DappPubKey if not already populated by the caller (avoids a
  // redundant SELECT FILE + chunk-read round-trip when the outer flow already
  // called ReadDappPubKey before CardAuthenticateEx).
  if (ias->DappPubKey.isEmpty()) {
    ByteDynArray dappData;
    ias->ReadDappPubKey(dappData);
  }

  LOG_INFO("CardAuthenticateEx - Performing DH Exchange");

  progressCallBack(26, "InitExtAuthKeyParam");
  ias->InitExtAuthKeyParam();

  progressCallBack(28, "DHKeyExchange");
  ias->DHKeyExchange();

  progressCallBack(30, "DAPP");
  ias->DAPP();

  progressCallBack(32, "VerifyPIN");

  // Verify PIN
  StatusWord sw;
  if (PinId == ROLE_USER) {
    LOG_INFO("CardAuthenticateEx - Verifying PIN");
    ByteDynArray PIN;
    if ((dwFlags & FULL_PIN) != FULL_PIN) ias->GetFirstPIN(PIN);
    PIN.append(ByteArray(pbPinData, cbPinData));
    sw = ias->VerifyPIN(PIN);
    OPENSSL_cleanse(PIN.data(), PIN.size());
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
      auto ris = conn->transport.Reconnect(conn->hCard, SCARD_SHARE_SHARED,
                                           SCARD_PROTOCOL_Tx,
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
                                           SCARD_PROTOCOL_Tx, SCARD_RESET_CARD,
                                           &protocol);
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

  if (ris == static_cast<LONG>(SCARD_W_RESET_CARD) ||
      ris == static_cast<LONG>(SCARD_W_UNPOWERED_CARD)) {
    LOG_INFO("TokenTransmitCallback - Card Reset done");

    DWORD protocol = 0;
    ris = conn->transport.Reconnect(conn->hCard, SCARD_SHARE_SHARED,
                                    SCARD_PROTOCOL_Tx, SCARD_LEAVE_CARD,
                                    &protocol);
    if (ris != SCARD_S_SUCCESS)
      LOG_ERROR("TokenTransmitCallback - ScardReconnect error: %d", ris);
    else {
      ris = conn->transport.Transmit(conn->hCard, SCARD_PCI_T1, apdu, apduSize,
                                     resp, respSize);
      LOG_DEBUG("TokenTransmitCallback - Smart card response:");
      LOG_BUFFER(resp, *respSize);
    }
  }

  if (ris != SCARD_S_SUCCESS) {
    LOG_ERROR("TokenTransmitCallback - SCardTransmit error: %d", ris);
  }
  return ris;
}

bool file_exists(const char* name);

#ifdef _WIN32
// Resolve cieid to an absolute path under ProgramFiles to avoid
// PATH/CWD-based binary hijack via CreateProcessA's search order.
static std::string getCieidPath() {
  const char* pf = std::getenv("ProgramFiles");
  if (!pf) pf = "C:\\Program Files";
  return std::string(pf) + "\\CIE\\cieid.exe";
}

DWORD WINAPI mythread(LPVOID thr_data) {
  char* command = static_cast<char*>(thr_data);
  STARTUPINFOA si {};
  si.cb = sizeof(si);
  PROCESS_INFORMATION pi {};
  std::string app = getCieidPath();
  CreateProcessA(app.c_str(), command, nullptr, nullptr, FALSE, 0, nullptr,
                 nullptr, &si, &pi);
  if (pi.hProcess) {
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
  }
  if (pi.hThread) CloseHandle(pi.hThread);
  delete[] command;
  return 0;
}
#else
void mythread(std::string cmd) {
  // Split cmd into program and arg; the program name itself is never
  // trusted here (see the fixed absolute path below), it only forwards
  // the argument built by sendMessage().
  auto space = cmd.find(' ');
  std::string arg = (space != std::string::npos) ? cmd.substr(space + 1) : "";
  pid_t pid;
  const char* argv[] = {"cieid", arg.c_str(), nullptr};
  if (posix_spawn(&pid, "/usr/bin/cieid", nullptr, nullptr,
                  const_cast<char* const*>(argv), environ) == 0) {
    waitpid(pid, nullptr, 0);
  }
}
#endif

int sendMessage(const char* szCommand, const char* /*szParam*/) {
  const char* file = "cieid";

#ifdef _WIN32
  // Heap-allocate to avoid race on a shared buffer
  size_t len = strlen(file) + 1 + strlen(szCommand) + 1;
  char* command = new char[len];
  snprintf(command, len, "%s %s", file, szCommand);
  HANDLE hThread = CreateThread(nullptr, 0, mythread,
                                static_cast<void*>(command), 0, nullptr);
  if (hThread)
    CloseHandle(hThread);
  else
    delete[] command;
#else
  std::string command = std::string(file) + " " + szCommand;
  std::thread(mythread, std::move(command)).detach();
#endif

  return 0;
}

int CK_ENTRY cie_reader_count(void) {
#if defined(__ANDROID__)
  return 0;
#else
  PCSCTransport transport;
  SCARDCONTEXT hCtx = 0;
  if (transport.EstablishContext(SCARD_SCOPE_USER, &hCtx) != SCARD_S_SUCCESS)
    return 0;

  DWORD len = 0;
  LONG rv = transport.ListReaders(hCtx, nullptr, &len);
  if (rv != SCARD_S_SUCCESS || len <= 1) {
    transport.ReleaseContext(hCtx);
    return 0;
  }

  char* buf = static_cast<char*>(malloc(len));
  rv = transport.ListReaders(hCtx, buf, &len);
  int count = 0;
  if (rv == SCARD_S_SUCCESS) {
    for (const char* p = buf; p[0] != '\0'; p += strnlen(p, len) + 1)
      if (strstr(p, "Virtual") == nullptr) ++count;
  }
  free(buf);
  transport.ReleaseContext(hCtx);
  return count;
#endif
}

int CK_ENTRY cie_reader_watch([[maybe_unused]] int current_count) {
#if defined(__ANDROID__)
  return 0;
#else
  PCSCTransport transport;
  SCARDCONTEXT hCtx = 0;
  if (transport.EstablishContext(SCARD_SCOPE_USER, &hCtx) != SCARD_S_SUCCESS)
    return -1;

  SCARD_READERSTATE pnp {};
  pnp.szReader = "\\\\?PnP?\\Notification";
  pnp.dwCurrentState = SCARD_STATE_UNAWARE;

  // SCardGetStatusChange(INFINITE) makes this call uninterruptible, which
  // hangs any host process (Dart isolate, NSS, browsers, ...) that tries to
  // shut down while no reader-count change has happened yet. Poll with a
  // bounded timeout instead, retrying on SCARD_E_TIMEOUT, so the loop keeps
  // its "block until reader count changes" contract while still noticing
  // cooperative cancellation opportunities at each poll boundary.
  constexpr DWORD kWatchPollMs = 1000;

  while (true) {
    LONG rv = transport.GetStatusChange(hCtx, kWatchPollMs, &pnp, 1);
    if (rv == static_cast<LONG>(SCARD_E_TIMEOUT)) {
      // No PnP event yet; fall through to re-count readers below so a
      // change that raced with the timeout is still detected promptly.
    } else if (rv != SCARD_S_SUCCESS) {
      transport.ReleaseContext(hCtx);
      return -1;
    } else {
      pnp.dwCurrentState = pnp.dwEventState & ~SCARD_STATE_CHANGED;
    }

    int count = 0;
    DWORD len = 0;
    rv = transport.ListReaders(hCtx, nullptr, &len);
    if (rv == SCARD_S_SUCCESS && len > 1) {
      char* buf = static_cast<char*>(malloc(len));
      if (transport.ListReaders(hCtx, buf, &len) == SCARD_S_SUCCESS) {
        for (const char* p = buf; p[0] != '\0'; p += strnlen(p, len) + 1)
          ++count;
      }
      free(buf);
    }

    if (count != current_count) {
      transport.ReleaseContext(hCtx);
      return count;
    }
  }
#endif
}

int CK_ENTRY cie_reader_name(char* buf, int buf_len) {
  if (!buf || buf_len <= 0) return 0;
  buf[0] = '\0';
#if defined(__ANDROID__)
  return 0;
#else
  PCSCTransport transport;
  SCARDCONTEXT hCtx = 0;
  if (transport.EstablishContext(SCARD_SCOPE_USER, &hCtx) != SCARD_S_SUCCESS)
    return 0;

  DWORD len = 0;
  LONG rv = transport.ListReaders(hCtx, nullptr, &len);
  if (rv != SCARD_S_SUCCESS || len <= 1) {
    transport.ReleaseContext(hCtx);
    return 0;
  }

  char* readers = static_cast<char*>(malloc(len));
  rv = transport.ListReaders(hCtx, readers, &len);
  int found = 0;
  if (rv == SCARD_S_SUCCESS) {
    for (const char* p = readers; p[0] != '\0'; p += strnlen(p, len) + 1) {
      if (strstr(p, "Virtual") != nullptr) continue;

      // Probe state without blocking (timeout=0)
      SCARD_READERSTATE rs {};
      rs.szReader = p;
      rs.dwCurrentState = SCARD_STATE_UNAWARE;
      LONG sr = transport.GetStatusChange(hCtx, 0, &rs, 1);
      if (sr != SCARD_S_SUCCESS) continue;

      DWORD state = rs.dwEventState;
      if (state & SCARD_STATE_UNAVAILABLE) continue;

      // Accept: card present, OR empty reader that isn't the built-in Broadcom
      bool hasCard = (state & SCARD_STATE_PRESENT) != 0;
      bool isEmpty = (state & SCARD_STATE_EMPTY) != 0;
      bool isInternal = strstr(p, "Broadcom") != nullptr;

      if (hasCard || (isEmpty && !isInternal)) {
        strncpy(buf, p, static_cast<size_t>(buf_len) - 1);
        buf[buf_len - 1] = '\0';
        found = 1;
        break;
      }
    }
  }
  free(readers);
  transport.ReleaseContext(hCtx);
  return found;
#endif
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
