// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file cie_p11_template.cpp
 * @brief CIE-specific card template callbacks implementation
 */

#include "pkcs11/cie_p11_template.h"

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <cstdio>
#include <cstring>
#include <memory>

#include "crypto/aes.h"
#include "crypto/asn_parser.h"
#include "csp/ias.h"
#include "pcsc/card_locker.h"
#include "pcsc/pcsc.h"

extern CLog Log;

#include "logger/logger.h"

using namespace CieIDLogger;
using namespace p11;

void notifyPINLocked();
void notifyPINWrong(int trials);

void GetCertInfo(const uint8_t *certDer, size_t certLen, std::string &serial,
                 ByteDynArray &issuerOut, ByteDynArray &subjectOut,
                 std::string &notBefore, std::string &notAfter,
                 ByteDynArray &modOut, ByteDynArray &pubExpOut);

static HRESULT TokenTransmitCallback(void *data, BYTE *apdu, DWORD apduSize,
                                     BYTE *resp, DWORD *respSize) {
  auto *slot = static_cast<CSlot *>(data);
  if (apduSize == 2) {
    WORD code = *reinterpret_cast<WORD *>(apdu);
    if (code == 0xfffd) {
      *respSize = sizeof(slot->hCard) + 2;
      std::memcpy(resp, &slot->hCard, sizeof(slot->hCard));
      resp[sizeof(slot->hCard)] = 0;
      resp[sizeof(slot->hCard) + 1] = 0;

      return SCARD_S_SUCCESS;
    } else if (code == 0xfffe) {
      DWORD protocol = 0;
      auto ris = slot->transport.Reconnect(slot->hCard, SCARD_SHARE_SHARED,
                                           SCARD_PROTOCOL_Tx,
                                           SCARD_UNPOWER_CARD, &protocol);

      if (ris == SCARD_S_SUCCESS) {
        slot->transport.BeginTransaction(slot->hCard);
        *respSize = 2;
        resp[0] = 0x90;
        resp[1] = 0x00;
      }
      return ris;
    } else if (code == 0xffff) {
      DWORD protocol = 0;
      auto ris = slot->transport.Reconnect(slot->hCard, SCARD_SHARE_SHARED,
                                           SCARD_PROTOCOL_Tx, SCARD_RESET_CARD,
                                           &protocol);
      if (ris == SCARD_S_SUCCESS) {
        slot->transport.BeginTransaction(slot->hCard);
        *respSize = 2;
        resp[0] = 0x90;
        resp[1] = 0x00;
      }
      return ris;
    }
  }

  auto ris = slot->transport.Transmit(slot->hCard, SCARD_PCI_T1, apdu, apduSize,
                                      resp, respSize);
  if (ris == static_cast<LONG>(SCARD_W_RESET_CARD) ||
      ris == static_cast<LONG>(SCARD_W_UNPOWERED_CARD)) {
    LOG_ERROR("TokenTransmitCallback - Card reset error: %x", ris);

    DWORD protocol = 0;
    ris = slot->transport.Reconnect(slot->hCard, SCARD_SHARE_SHARED,
                                    SCARD_PROTOCOL_Tx, SCARD_LEAVE_CARD,
                                    &protocol);
    if (ris != SCARD_S_SUCCESS) {
      LOG_ERROR("TokenTransmitCallback - Reconnect error %d", ris);
    } else {
      ris = slot->transport.Transmit(slot->hCard, SCARD_PCI_T1, apdu, apduSize,
                                     resp, respSize);
    }
  }

  if (ris != SCARD_S_SUCCESS) {
    LOG_ERROR("TokenTransmitCallback - APDU transmission error: %x", ris);
  }

  return ris;
}

class CIEData {
 public:
  CK_USER_TYPE userType;
  CAES aesKey;
  CToken token;
  bool init;
  CIEData(CSlot *slot, ByteArray atr)
      : slot(*slot), ias(TokenTransmitCallback, atr) {
    ByteDynArray key(32);
    ByteDynArray iv(16);
    aesKey.Init(key.random(), iv.random());
    token.setTransmitCallbackData(slot);
    userType = -1;
    init = false;
  }
  CSlot &slot;
  IAS ias;
  std::shared_ptr<CP11PublicKey> pubKey;
  std::shared_ptr<CP11PrivateKey> privKey;
  std::shared_ptr<CP11Certificate> cert;
  ByteDynArray SessionPIN;
};

void CIEtemplateInitLibrary(class CCardTemplate & /*Template*/,
                            void * /*templateData*/) {
  return;
}
void CIEtemplateInitCard(void *&pTemplateData, CSlot &pSlot) {
  init_func ByteArray ATR;
  pSlot.GetATR(ATR);

  pTemplateData = new CIEData(&pSlot, ATR);
}
void CIEtemplateFinalCard(void *pTemplateData) {
  if (pTemplateData) delete static_cast<CIEData *>(pTemplateData);
}

ByteArray SkipZero(const ByteArray &ba) {
  for (DWORD i = 0; i < ba.size(); i++) {
    if (ba[i] != 0) return ba.mid(i);
  }
  return ByteArray();
}

void CIEtemplateInitSession(void *pTemplateData) {
  CIEData *cie = static_cast<CIEData *>(pTemplateData);

  if (!cie->init) {
    ByteDynArray certRaw;
    cie->slot.Connect();
    {
      safeConnection faseConn(cie->slot.transport, cie->slot.hCard);
      CCardLocker lockCard(cie->slot.transport, cie->slot.hCard);
      cie->ias.SetCardContext(&cie->slot);
      cie->ias.SelectAID_IAS();
      cie->ias.ReadPAN();

      ByteDynArray resp;
      cie->ias.SelectAID_CIE();
      cie->ias.ReadDappPubKey(resp);
      cie->ias.InitEncKey();
      cie->ias.GetCertificate(certRaw, true);
    }

    CK_BBOOL vtrue = TRUE;
    CK_BBOOL vfalse = FALSE;
    BYTE labelCert[] = "CIE Certificate";
    BYTE labelPriv[] = "CIE Private Key";
    BYTE labelPub[] = "CIE Public Key";
    CK_BYTE objId = 0x01;  // For simplicity we only need one (numbered '1')

    cie->pubKey = std::make_shared<CP11PublicKey>(cie);
    cie->privKey = std::make_shared<CP11PrivateKey>(cie);
    cie->cert = std::make_shared<CP11Certificate>(cie);

    cie->pubKey->addAttribute(CKA_LABEL, VarToByteArray(labelPub));
    cie->pubKey->addAttribute(CKA_ID, VarToByteArray(objId));
    cie->pubKey->addAttribute(CKA_PRIVATE, VarToByteArray(vfalse));
    cie->pubKey->addAttribute(CKA_TOKEN, VarToByteArray(vtrue));
    cie->pubKey->addAttribute(CKA_VERIFY, VarToByteArray(vtrue));
    CK_KEY_TYPE keyrsa = CKK_RSA;
    cie->pubKey->addAttribute(CKA_KEY_TYPE, VarToByteArray(keyrsa));

    cie->privKey->addAttribute(CKA_LABEL, VarToByteArray(labelPriv));
    cie->privKey->addAttribute(CKA_ID, VarToByteArray(objId));
    cie->privKey->addAttribute(CKA_PRIVATE, VarToByteArray(vtrue));
    cie->privKey->addAttribute(CKA_TOKEN, VarToByteArray(vtrue));
    cie->privKey->addAttribute(CKA_KEY_TYPE, VarToByteArray(keyrsa));

    cie->privKey->addAttribute(CKA_SIGN, VarToByteArray(vtrue));

    cie->cert->addAttribute(CKA_LABEL, VarToByteArray(labelCert));
    cie->cert->addAttribute(CKA_ID, VarToByteArray(objId));
    cie->cert->addAttribute(CKA_PRIVATE, VarToByteArray(vfalse));
    cie->cert->addAttribute(CKA_TOKEN, VarToByteArray(vtrue));

    CK_CERTIFICATE_TYPE certx509 = CKC_X_509;
    cie->cert->addAttribute(CKA_CERTIFICATE_TYPE, VarToByteArray(certx509));

    std::string serial;
    ByteDynArray issuerBa;
    ByteDynArray subjectBa;
    std::string notBefore;
    std::string notAfter;
    ByteDynArray modulus;
    ByteDynArray publicExponent;

    GetCertInfo(certRaw.data(), certRaw.size(), serial, issuerBa, subjectBa,
                notBefore, notAfter, modulus, publicExponent);

    CK_LONG keySizeBits = static_cast<CK_LONG>(modulus.size()) * 8;

    cie->pubKey->addAttribute(CKA_MODULUS, modulus);
    cie->pubKey->addAttribute(CKA_PUBLIC_EXPONENT, publicExponent);
    cie->pubKey->addAttribute(CKA_MODULUS_BITS, VarToByteArray(keySizeBits));

    cie->privKey->addAttribute(CKA_MODULUS, modulus);
    cie->privKey->addAttribute(CKA_PUBLIC_EXPONENT, publicExponent);

    cie->cert->addAttribute(CKA_ISSUER, issuerBa);
    cie->cert->addAttribute(
        CKA_SERIAL_NUMBER,
        ByteArray(reinterpret_cast<const BYTE *>(serial.c_str()),
                  serial.size()));
    cie->cert->addAttribute(CKA_SUBJECT, subjectBa);

    CK_DATE start, end;

    char sFrom[8], sTo[8];
    memcpy(sFrom, notBefore.c_str(), 8);
    memcpy(sTo, notAfter.c_str(), 8);

    VarToByteArray(start.year)
        .copy(ByteArray(reinterpret_cast<BYTE *>(sFrom), 4));
    VarToByteArray(start.month)
        .copy(ByteArray(reinterpret_cast<BYTE *>(&sFrom[4]), 2));
    VarToByteArray(start.day).copy(
        ByteArray(reinterpret_cast<BYTE *>(&sFrom[6]), 2));

    VarToByteArray(end.year).copy(ByteArray(reinterpret_cast<BYTE *>(sTo), 4));
    VarToByteArray(end.month).copy(
        ByteArray(reinterpret_cast<BYTE *>(&sTo[4]), 2));
    VarToByteArray(end.day).copy(
        ByteArray(reinterpret_cast<BYTE *>(&sTo[6]), 2));

    cie->cert->addAttribute(CKA_START_DATE, VarToByteArray(start));
    cie->cert->addAttribute(CKA_END_DATE, VarToByteArray(end));

    // add to the object
    size_t len = GetASN1DataLenght(certRaw);
    cie->cert->addAttribute(CKA_VALUE, certRaw.left(len));

    cie->slot.AddP11Object(cie->pubKey);
    cie->slot.AddP11Object(cie->privKey);
    cie->slot.AddP11Object(cie->cert);

    cie->init = true;
  }
}
void CIEtemplateFinalSession(void * /*pTemplateData*/) {}

bool CIEtemplateMatchCard(CSlot &pSlot) {
  init_func CToken token;

  pSlot.Connect();
  {
    safeConnection faseConn(pSlot.transport, pSlot.hCard);
    ByteArray ATR;
    pSlot.GetATR(ATR);
    token.setTransmitCallback(TokenTransmitCallback, &pSlot);
    IAS ias(TokenTransmitCallback, ATR);
    ias.SetCardContext(&pSlot);
    {
      safeTransaction trans(pSlot.transport, faseConn, SCARD_LEAVE_CARD);
      ias.SelectAID_IAS();
      ias.ReadPAN();
    }
    return true;
  }
}

ByteDynArray CIEtemplateGetSerial(CSlot &pSlot) {
  init_func CToken token;

  pSlot.Connect();
  {
    safeConnection faseConn(pSlot.transport, pSlot.hCard);
    CCardLocker lockCard(pSlot.transport, pSlot.hCard);
    ByteArray ATR;
    pSlot.GetATR(ATR);
    IAS ias(TokenTransmitCallback, ATR);
    ias.SetCardContext(&pSlot);
    ias.SelectAID_IAS();
    ias.ReadPAN();
    std::string numSerial;
    dumpHexData(ias.PAN.mid(5, 6), numSerial, false);
    return ByteDynArray(ByteArray(
        reinterpret_cast<const BYTE *>(numSerial.c_str()), numSerial.length()));
  }
}
void CIEtemplateGetModel(CSlot & /*pSlot*/, std::string &szModel) {
  szModel = "CIE 3.0";
}
void CIEtemplateGetTokenFlags(CSlot & /*pSlot*/, CK_FLAGS &dwFlags) {
  dwFlags = CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED |
            CKF_TOKEN_INITIALIZED | CKF_REMOVABLE_DEVICE;
}

void CIEtemplateLogin(void *pTemplateData, CK_USER_TYPE userType,
                      const ByteArray &Pin) {
  init_func CToken token;
  CIEData *cie = static_cast<CIEData *>(pTemplateData);

  cie->SessionPIN.clear();
  cie->userType = -1;

  cie->slot.Connect();
  cie->ias.SetCardContext(&cie->slot);
  cie->ias.token.Reset();
  {
    safeConnection safeConn(cie->slot.transport, cie->slot.hCard);
    CCardLocker lockCard(cie->slot.transport, cie->slot.hCard);

    cie->ias.SelectAID_IAS();
    cie->ias.SelectAID_CIE();
    cie->ias.InitDHParam();

    if (cie->ias.DappPubKey.isEmpty()) {
      ByteDynArray DappKey;
      cie->ias.ReadDappPubKey(DappKey);
    }

    cie->ias.InitExtAuthKeyParam();
    // perform DH key exchange
    if (cie->ias.Callback != nullptr)
      cie->ias.Callback(1, "DiffieHellman", cie->ias.CallbackData);
    cie->ias.DHKeyExchange();
    cie->ias.DAPP();
    // Verify PIN
    StatusWord sw;
    if (cie->ias.Callback != nullptr)
      cie->ias.Callback(3, "Verify PIN", cie->ias.CallbackData);
    if (userType == CKU_USER) {
      ByteDynArray FullPIN;
      cie->ias.GetFirstPIN(FullPIN);
      FullPIN.append(Pin);
      sw = cie->ias.VerifyPIN(FullPIN);
    } else if (userType == CKU_SO) {
      sw = cie->ias.VerifyPUK(Pin);
    } else {
      throw p11_error(CKR_ARGUMENTS_BAD);
    }

    if (sw == 0x6983) {
      if (userType == CKU_USER) {
        notifyPINLocked();
        throw p11_error(CKR_PIN_LOCKED);
      }
    }
    if (sw >= 0x63C0 && sw <= 0x63CF) {
      int attemptsRemaining = sw - 0x63C0;
      notifyPINWrong(attemptsRemaining);
      throw p11_error(CKR_PIN_INCORRECT);
    }
    if (sw == 0x6700) {
      notifyPINWrong(-1);
      throw p11_error(CKR_PIN_INCORRECT);
    }
    if (sw == 0x6300) {
      notifyPINWrong(-1);
      throw p11_error(CKR_PIN_INCORRECT);
    }
    if (sw != 0x9000) {
      throw scard_error(sw);
    }

    cie->SessionPIN = cie->aesKey.Encode(Pin);
    cie->userType = userType;
  }
}
void CIEtemplateLogout(void *pTemplateData, CK_USER_TYPE /*userType*/) {
  CIEData *cie = static_cast<CIEData *>(pTemplateData);
  cie->userType = -1;
  cie->SessionPIN.clear();
}
void CIEtemplateReadObjectAttributes(void * /*pCardTemplateData*/,
                                     CP11Object * /*pObject*/) {}
void CIEtemplateSign(void *pCardTemplateData, CP11PrivateKey * /*pPrivKey*/,
                     const ByteArray &baSignBuffer, ByteDynArray &baSignature,
                     CK_MECHANISM_TYPE /*mechanism*/, bool /*bSilent*/) {
  init_func CToken token;
  CIEData *cie = static_cast<CIEData *>(pCardTemplateData);
  if (cie->userType == CKU_USER) {
    ByteDynArray Pin;
    cie->slot.Connect();
    cie->ias.SetCardContext(&cie->slot);
    cie->ias.token.Reset();
    {
      safeConnection safeConn(cie->slot.transport, cie->slot.hCard);
      CCardLocker lockCard(cie->slot.transport, cie->slot.hCard);

      Pin = cie->aesKey.Decode(cie->SessionPIN);
      cie->ias.SelectAID_IAS();
      cie->ias.SelectAID_CIE();
      cie->ias.DHKeyExchange();
      cie->ias.DAPP();

      ByteDynArray FullPIN;
      cie->ias.GetFirstPIN(FullPIN);
      FullPIN.append(Pin);
      if (cie->ias.VerifyPIN(FullPIN) != 0x9000)
        throw p11_error(CKR_PIN_INCORRECT);
      cie->ias.Sign(baSignBuffer, baSignature);
    }
  }
}

void CIEtemplateInitPIN(void *pCardTemplateData, const ByteArray &baPin) {
  init_func CToken token;
  CIEData *cie = static_cast<CIEData *>(pCardTemplateData);
  if (cie->userType == CKU_SO) {
    // can only use it if logged in as SO
    ByteDynArray Pin;
    cie->slot.Connect();
    cie->ias.SetCardContext(&cie->slot);
    cie->ias.token.Reset();
    {
      safeConnection safeConn(cie->slot.transport, cie->slot.hCard);
      CCardLocker lockCard(cie->slot.transport, cie->slot.hCard);

      Pin = cie->aesKey.Decode(cie->SessionPIN);
      cie->ias.SelectAID_IAS();
      cie->ias.SelectAID_CIE();

      cie->ias.DHKeyExchange();
      cie->ias.DAPP();
      if (cie->ias.VerifyPUK(Pin) != 0x9000) throw p11_error(CKR_PIN_INCORRECT);

      if (cie->ias.UnblockPIN() != 0x9000) throw p11_error(CKR_GENERAL_ERROR);

      ByteDynArray changePIN;
      cie->ias.GetFirstPIN(changePIN);
      changePIN.append(baPin);

      if (cie->ias.ChangePIN(changePIN) != 0x9000)
        throw p11_error(CKR_GENERAL_ERROR);
    }
  } else {
    throw p11_error(CKR_FUNCTION_NOT_SUPPORTED);
  }
}

void CIEtemplateSetPIN(void *pCardTemplateData, const ByteArray &baOldPin,
                       const ByteArray &baNewPin, CK_USER_TYPE /*User*/) {
  init_func CToken token;
  CIEData *cie = static_cast<CIEData *>(pCardTemplateData);
  if (cie->userType != CKU_SO) {
    // can use it whether logged in as user or not logged in
    ByteDynArray Pin;
    cie->slot.Connect();
    cie->ias.SetCardContext(&cie->slot);
    cie->ias.token.Reset();
    {
      safeConnection safeConn(cie->slot.transport, cie->slot.hCard);
      CCardLocker lockCard(cie->slot.transport, cie->slot.hCard);
      cie->ias.SelectAID_IAS();
      if (cie->userType != CKU_USER) cie->ias.InitDHParam();
      cie->ias.SelectAID_CIE();

      if (cie->userType != CKU_USER) {
        cie->ias.ReadPAN();
        ByteDynArray resp;
        cie->ias.ReadDappPubKey(resp);
      }

      cie->ias.DHKeyExchange();
      cie->ias.DAPP();
      ByteDynArray oldPIN, newPIN;
      cie->ias.GetFirstPIN(oldPIN);
      newPIN = oldPIN;
      oldPIN.append(baOldPin);
      newPIN.append(baNewPin);

      if (cie->ias.VerifyPIN(oldPIN) != 0x9000)
        throw p11_error(CKR_PIN_INCORRECT);
      if (cie->ias.ChangePIN(oldPIN, newPIN) != 0x9000)
        throw p11_error(CKR_GENERAL_ERROR);
    }
  } else {
    throw p11_error(CKR_FUNCTION_NOT_SUPPORTED);
  }
}

void CIEtemplateSignRecover(void * /*pCardTemplateData*/,
                            CP11PrivateKey * /*pPrivKey*/,
                            ByteArray & /*baSignBuffer*/,
                            ByteDynArray & /*baSignature*/,
                            CK_MECHANISM_TYPE /*mechanism*/, bool /*bSilent*/) {
  throw p11_error(CKR_FUNCTION_NOT_SUPPORTED);
}
void CIEtemplateDecrypt(void * /*pCardTemplateData*/,
                        CP11PrivateKey * /*pPrivKey*/,
                        ByteArray & /*baEncryptedData*/,
                        ByteDynArray & /*baData*/,
                        CK_MECHANISM_TYPE /*mechanism*/, bool /*bSilent*/) {
  throw p11_error(CKR_FUNCTION_NOT_SUPPORTED);
}
void CIEtemplateGenerateRandom(void * /*pCardTemplateData*/,
                               ByteArray & /*baRandomData*/) {
  throw p11_error(CKR_FUNCTION_NOT_SUPPORTED);
}
CK_ULONG CIEtemplateGetObjectSize(void * /*pCardTemplateData*/,
                                  CP11Object * /*pObject*/) {
  throw p11_error(CKR_FUNCTION_NOT_SUPPORTED);
}
void CIEtemplateSetKeyPIN(void * /*pTemplateData*/, CP11Object * /*pObject*/,
                          ByteArray & /*Pin*/) {
  throw p11_error(CKR_FUNCTION_NOT_SUPPORTED);
}
void CIEtemplateSetAttribute(void * /*pTemplateData*/, CP11Object * /*pObject*/,
                             CK_ATTRIBUTE_PTR /*pTemplate*/,
                             CK_ULONG /*ulCount*/) {
  throw p11_error(CKR_FUNCTION_NOT_SUPPORTED);
}
std::shared_ptr<CP11Object> CIEtemplateCreateObject(
    void * /*pTemplateData*/, CK_ATTRIBUTE_PTR /*pTemplate*/,
    CK_ULONG /*ulCount*/) {
  throw p11_error(CKR_FUNCTION_NOT_SUPPORTED);
}
void CIEtemplateDestroyObject(void * /*pTemplateData*/,
                              CP11Object & /*Object*/) {
  throw p11_error(CKR_FUNCTION_NOT_SUPPORTED);
}
std::shared_ptr<CP11Object> CIEtemplateGenerateKey(
    void * /*pCardTemplateData*/, CK_MECHANISM_PTR /*pMechanism*/,
    CK_ATTRIBUTE_PTR /*pTemplate*/, CK_ULONG /*ulCount*/) {
  throw p11_error(CKR_FUNCTION_NOT_SUPPORTED);
}
void CIEtemplateGenerateKeyPair(void * /*pCardTemplateData*/,
                                CK_MECHANISM_PTR /*pMechanism*/,
                                CK_ATTRIBUTE_PTR /*pPublicKeyTemplate*/,
                                CK_ULONG /*ulPublicKeyAttributeCount*/,
                                CK_ATTRIBUTE_PTR /*pPrivateKeyTemplate*/,
                                CK_ULONG /*ulPrivateKeyAttributeCount*/,
                                std::shared_ptr<CP11Object> & /*pPublicKey*/,
                                std::shared_ptr<CP11Object> & /*pPrivateKey*/) {
  throw p11_error(CKR_FUNCTION_NOT_SUPPORTED);
}

/**
 * Reads an X.509 v3 certificate from certDer, extracts the
 * subjectPublicKeyInfo structure (which is one way PK_Verifiers can get
 * their key material) plus the issuer and serial number.
 *
 * @throws logged_error if the certificate cannot be parsed
 */

void GetPublicKeyFromCert(const uint8_t *certDer, size_t certLen,
                          ByteDynArray &pubKeyOut, ByteDynArray &issuerOut,
                          ByteDynArray &serialOut) {
  const unsigned char *p = certDer;
  X509 *x509 = d2i_X509(nullptr, &p, static_cast<long>(certLen));
  if (!x509) throw logged_error("Failed to parse X.509 certificate");

  // Subject Public Key Info (DER)
  unsigned char *spki = nullptr;
  int spkiLen = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(x509), &spki);
  if (spkiLen > 0 && spki) {
    pubKeyOut.resize(spkiLen);
    pubKeyOut.copy(ByteArray(spki, spkiLen));
    OPENSSL_free(spki);
  }

  // Issuer (DER)
  unsigned char *issuerDer = nullptr;
  int issuerLen = i2d_X509_NAME(X509_get_issuer_name(x509), &issuerDer);
  if (issuerLen > 0 && issuerDer) {
    issuerOut.resize(issuerLen);
    issuerOut.copy(ByteArray(issuerDer, issuerLen));
    OPENSSL_free(issuerDer);
  }

  // Serial
  const ASN1_INTEGER *serial = X509_get0_serialNumber(x509);
  BIGNUM *bn = ASN1_INTEGER_to_BN(serial, nullptr);
  if (bn) {
    int sLen = BN_num_bytes(bn);
    serialOut.resize(sLen);
    BN_bn2bin(bn, serialOut.data());
    BN_free(bn);
  }

  X509_free(x509);
}

void GetCertInfo(const uint8_t *certDer, size_t certLen, std::string &serial,
                 ByteDynArray &issuerOut, ByteDynArray &subjectOut,
                 std::string &notBefore, std::string &notAfter,
                 ByteDynArray &modOut, ByteDynArray &pubExpOut) {
  const unsigned char *p = certDer;
  X509 *x509_raw = d2i_X509(nullptr, &p, static_cast<long>(certLen));
  if (!x509_raw) throw logged_error("Failed to parse X.509 certificate");
  std::unique_ptr<X509, decltype(&X509_free)> x509_guard(x509_raw, &X509_free);
  X509 *x509 = x509_guard.get();

  // Serial (decimal string, matching pre-existing consumer expectations)
  BIGNUM *bn = ASN1_INTEGER_to_BN(X509_get0_serialNumber(x509), nullptr);
  if (!bn) {
    throw logged_error("Failed to read certificate serial number");
  }
  char *dec = BN_bn2dec(bn);
  serial = dec;
  OPENSSL_free(dec);
  BN_free(bn);

  // Issuer / subject (DER)
  unsigned char *issuerDer = nullptr;
  int issuerLen = i2d_X509_NAME(X509_get_issuer_name(x509), &issuerDer);
  if (issuerLen > 0 && issuerDer) {
    issuerOut.resize(issuerLen);
    issuerOut.copy(ByteArray(issuerDer, issuerLen));
    OPENSSL_free(issuerDer);
  }

  unsigned char *subjectDer = nullptr;
  int subjectLen = i2d_X509_NAME(X509_get_subject_name(x509), &subjectDer);
  if (subjectLen > 0 && subjectDer) {
    subjectOut.resize(subjectLen);
    subjectOut.copy(ByteArray(subjectDer, subjectLen));
    OPENSSL_free(subjectDer);
  }

  // Validity — keep the YYYYMMDD... GeneralizedTime layout callers expect.
  auto timeToStr = [](const ASN1_TIME *t) -> std::string {
    ASN1_GENERALIZEDTIME *gt = ASN1_TIME_to_generalizedtime(t, nullptr);
    if (!gt) throw logged_error("Failed to convert certificate time");
    std::string s(reinterpret_cast<const char *>(ASN1_STRING_get0_data(gt)),
                  static_cast<size_t>(ASN1_STRING_length(gt)));
    ASN1_STRING_free(gt);
    return s;
  };
  notBefore = timeToStr(X509_get0_notBefore(x509));
  notAfter = timeToStr(X509_get0_notAfter(x509));

  // RSA modulus / public exponent
  EVP_PKEY *pkey = X509_get0_pubkey(x509);
  if (pkey && EVP_PKEY_base_id(pkey) == EVP_PKEY_RSA) {
    BIGNUM *n = nullptr;
    BIGNUM *e = nullptr;
    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n);
    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e);

    if (n) {
      int nLen = BN_num_bytes(n);
      modOut.resize(nLen);
      BN_bn2bin(n, modOut.data());
      BN_free(n);
    }
    if (e) {
      int eLen = BN_num_bytes(e);
      pubExpOut.resize(eLen);
      BN_bn2bin(e, pubExpOut.data());
      BN_free(e);
    }
  }
}
